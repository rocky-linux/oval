import time
import datetime as dt

namespace = {
    'Common'          : 'oval',
    'Definitions'     : 'oval-def',
    'Results'         : 'oval-res',
    'Variables'       : 'oval-var',
    'Directives'      : 'oval-dir',
    'Characteristics' : 'oval-sc',
    'External'        : 'ext',
}

baseurl = 'http://oval.mitre.org/XMLSchema/'
baserule = baseurl + 'oval-definitions-5'

publication_date = dt.datetime.utcnow()
copyright = 'Copyright ' + str( publication_date.year ) + ' Rocky Enterprise Software Foundation, Inc.'

version = {
    'Product' : "1",
    'Schema'  : "5.10",
    'Scope'   : "oval:org.rockylinux.rlsa:",
    'Tag'     : "red-def:"
}

""" 
    OVAL definitions specifies what to check and what values
    OVAL object specifies what to check
    OVAL state specifies what's expected
    OVAL test associates objects and states (provides boolean result)
    OVAL criteria describes an assertion to be satisfied
"""

def escape( description ) :
    """
    escape special characters from description string
    """

    # clean any symbols in description
    description = description.replace( '&', "&amp;")
    description = description.replace( '<', "&lt;" )
    description = description.replace( '>', "&gt;" )
    description = description.replace( '"', "&quot;")
    
    return description


def section( name, close = False ) :
    """
    section tag helper for open or close
    """

    xml = '</' if close else '<'
    xml = xml + name + '>'

    return xml


def header( version ) :
    """
    header for all OVAL generated files
    """

    xml = '<?xml version="1.0" encoding="utf-8"?>\n' + \
          '<oval_definitions\n' + \
          '    xmlns="' + baserule + '"\n' + \
          '    xmlns:oval="' + baseurl + 'oval-common-5"\n' + \
          '    xmlns:unix-def="' + baserule + '#unix"\n' + \
          '    xmlns:red-def="' + baserule + '#linux"\n' + \
          '    xmlns:ind-def="' + baserule + '#independent"\n' + \
          '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' + \
          '    xsi:schemaLocation="' + baseurl + 'oval-common-5 oval-common-schema.xsd ' + \
          baserule + ' oval-definitions-schema.xsd ' + \
          baserule + '#unix unix-definitions-schema.xsd ' + \
          baserule + '#linux linux-definitions-schema.xsd">\n'

    xml = xml + \
          '<generator>\n' + \
          '<oval:product_name>Rocky OVAL Patch Definition Merger</oval:product_name>\n' + \
          '<oval:product_version>' + version[ "Product" ] + '</oval:product_version>\n' + \
          '<oval:schema_version>' + version[ "Schema" ] + '</oval:schema_version>\n' + \
          '<oval:timestamp>' + publication_date.strftime( "%Y-%m-%dT%H:%M:%S" ) + '</oval:timestamp>\n' + \
          '<oval:content_version>' + str( int( time.mktime( publication_date.timetuple( ) ) ) ) + '</oval:content_version>\n' + \
          '</generator>'

    return xml


def footer( ) :
    """
    footer for all OVAL generated files
    """
    
    xml = '</oval_definitions>'

    return xml

    
def definition( scope, did, dversion, dclass, metadata, criteria ) :
    """
    definition can describe a class which categorizes the content contained
    within it which includes metadata and criteria with valid classes of
    compliance, inventory, miscellaneous, patch, vulnerability
    """

    xml = '<definition class="' + dclass + '" id="' + scope + 'def:' + did + '" version="' + dversion + '">\n' + \
          metadata + \
          criteria + \
          '</definition>'

    return xml


def metadata( title, family, platforms, ref_id, source, references, description, 
    severity, issued, updated, cpes, rl_version ) :
    """
    metadata element contains information about the definition but
    does not affect evaluation of the definition
    """

    xml = '  <metadata>\n' + \
          '    <title>' + title + '</title>\n' + \
          '    <affected family="' + family + '">\n'

    for platform in platforms :
        xml = xml + \
              '      <platform>' + platform + '</platform>\n'

    xml = xml + \
          '    </affected>\n'

    xml = xml + \
          '    <reference ref_id="' + ref_id + \
          '" ref_url="https://errata.rockylinux.org/' + ref_id + \
          '" source="' + source + '"/>\n'

    for reference in references :
        xml = xml + \
              '    <reference ref_id="' + reference[ 'id' ] + '" ref_url="' + \
                  reference[ 'url' ] + '" source="' + reference[ 'source' ] + '"/>\n'

    xml = xml + \
          '    <description>' + escape( description ) + '</description>\n'

    xml = xml + \
          '    <advisory from="cpe:/o:rocky:rocky:' + str( rl_version ) + ':GA">\n' + \
          '      <severity>' + severity + '</severity>\n' + \
          '      <rights>' + copyright + '</rights>\n' + \
          '      <issued date="' + issued + '"/>\n' + \
          '      <updated date="' + updated + '"/>\n'

    cves = ''
    bugs = ''
    for reference in references :
        cves = cves + \
               '      <cve cvss3="' + reference[ 'cvss3' ] + '" cwe="' + \
               reference[ 'cwe' ] + '" href="' + reference[ 'url' ] + \
               '" impact="' + reference[ 'impact' ] + '" public="' + \
               reference[ 'public' ] + '">' + reference[ 'cve' ] + '</cve>\n'

        if 'bugref' in reference:
            bugs = bugs + \
                '      <bugzilla href="' + reference[ 'bugref' ] + '" id="' + \
                reference[ 'bugid' ] + '">' + reference[ 'bugdesc' ] + '</bugzilla>\n'

    xml = xml + \
          cves + \
          bugs + \
          '      <affected_cpe_list>\n'

    for cpe in cpes :
        xml = xml + \
              '        <cpe>' + cpe + '</cpe>\n'

    xml = xml + \
          '      </affected_cpe_list>\n' + \
          '    </advisory>\n' + \
          '  </metadata>\n'

    return xml


def criteria( scope, contents, xml = '' ) :
    """
    criteria defines logic expressions with zero or more
    criterion and nested criteria
    """

    for index, content in enumerate( contents ) :

        if content[ 'operator' ] != "" :
            xml = xml + '  <criteria operator="' + content[ 'operator' ] + '">\n'

        xml = xml + \
              '    <criterion comment="' + content[ 'comment' ] + '"\n' + \
              '      test_ref="' + scope + 'tst:' + content[ 'id' ] + '"/>\n'

        if content[ 'nested' ] :
            return criteria( scope, contents[index+1:], xml ) + '  </criteria>\n'

        if content[ 'operator' ] != "AND" :
            xml = xml + '  </criteria>\n'

    return xml
    

def test( tag, scope, ttype, tid, tversion, comment, check, oid, sids ) :
    """
    test defines the relationship between an object and
    zero or more states to be checked for corresponding value
    """

    xml = '  <' + tag + ttype + '_test check="' + check + '" comment="' + \
          comment + '" id="' + scope + 'tst:' + \
          tid + '" version="' + tversion + '">\n' + \
          '    <' + tag + 'object object_ref="' + scope + 'obj:' + oid + '"/>\n'

    for sid in sids :
        xml = xml + \
              '    <' + tag + 'state state_ref="' + scope + 'ste:' + sid + '"/>\n'

    xml = xml + \
          '  </' + tag + ttype + '_test>'

    return xml


def object( tag, scope, otype, oid, oversion, contents ) :
    """
    object says which information to collect for evaluation which
    can be uniquely identified for collection
    """

    xml = '  <' + tag + otype + '_object id="' + scope + 'obj:' + \
          oid + '" version="' + oversion + '">\n'

    for content in contents :

        xml = xml + '    <' + tag + content[ 'name' ] 

        if content[ 'operation' ] :
            xml = xml + ' operation="' + content[ 'operation' ] + '"'

        if content[ 'value' ] :
            xml = xml +  '>' + content[ 'value' ] + '</' + \
                  tag + content[ 'name' ] + '>\n'
        else :
            if content[ 'pairs' ] :
                for pair in content[ 'pairs' ] :
                    xml = xml + ' ' + pair[ 'name' ] + '="' + pair[ 'value' ] + '"'
            xml = xml + '/>\n'

    xml = xml + \
          '  </' + tag + otype + '_object>'

    return xml


def state( tag, scope, stype, sid, sversion, contents ) :
    """
    state says the expected values to be compared to the
    collected information
    """

    xml = '  <' + tag + stype + '_state id="' + scope + 'ste:' + \
          sid + '" version="' + sversion + '">\n'
    
    for content in contents :

        xml = xml + '    <' + tag + content[ 'name' ] 

        if content[ 'type' ] :
            xml = xml + ' datatype="' + content[ 'type' ] + '"'
            
        if content[ 'operation' ] :
            xml = xml + ' operation="' + content[ 'operation' ] + '"'

        if content[ 'value' ] :
            xml = xml +  '>' + content[ 'value' ] + '</' + \
                  tag + content[ 'name' ] + '>\n'
        else :
            xml = xml + '/>\n'

    
    xml = xml + \
          '  </' + tag + stype + '_state>'

    return xml


def variable( scope, vtype, vid, vversion, dtype, comment, values ) :
    """
    variable is a grouping of one or more values to be referenced
    within other content
    """

    xml = '  <rocky_def:' + vtype + '_variable id="' + scope + 'var:' + vid + '" version="' + \
          vversion + '"\n' + '    datatype="' + dtype + '"\n' + '    comment="' + \
          comment + '">\n'

    for value in values :
        xml = xml +  \
              '    <value>' + value + '</value>\n'
    
    xml = xml + \
          '  </' + vtype + '_variable>\n'

    return xml


def set( scope, stype, sid, sversion, rule, sop, oids ) :
    """
    set are logical combinations of objects which creates a grouping
    using the union operator over the objects contained
    """

    xml = '  <rocky_def:' + stype + '_object id="' + scope + 'obj:' + sid + '" version="' + \
          sversion + '"\n' + '    xmlns="' + baserule + rule + '">\n' + \
          '    <oval-def:set set_operator="' + sop + '">\n'

    for oid in oids :
        xml = xml +  \
          '      <oval-def:object_reference>' + scope + 'obj:' + oid + '\n' + \
          '      </oval-def:object_reference>\n'
    
    xml = xml + \
          '  </' + stype + '_object>\n'

    return xml


def filter( scope, otype, oid, oversion, rule, contents, faction, fid ) :
    """
    filter includes or excludes specific information from a grouping
    based on a state
    """

    xml = '  <rocky_def:' + otype + '_object id="' + scope + 'obj:' + oid + '" version="' + \
          oversion + '"\n' + '    xmlns="' + baserule + rule + '">\n'

    for content in contents :
        xml = xml + \
          '    <' + content[ 'name' ] + ' operation="' + content[ 'op' ] + '">' + \
          content[ 'value' ] + '</' + content[ 'name' ] + '>\n'

    xml = xml + \
          '  <oval-def:filter action="' + faction + '">' + scope + 'ste:' + fid + '\n' + \
          '  </oval-def:filter>\n' + \
          '  </' + otype + '_object>\n'
 
    return xml


def regex( scope, variant, type, id, version, comment, rule, contents ) :
    """
    regex support to increase the flexibility of definitions
    """

    if variant == "state" : tag = "ste"
    elif variant == "object" : tag = "obj"
    elif variant == "test" : tag = "tst"
    elif variant == "variable" : tag = "var"
    else : tag = "unk" 

    xml = '  <rocky_def:' + type + '_' + variant + ' id="' + scope + tag + ':' + id + '" version="' + \
          version + '"\n' + '    xmlns="' + baserule + rule + '"\n' + '    comment="' + \
          comment + '">\n'

    for content in contents :
        xml = xml + \
          '    <' + content[ 'name' ] + ' datatype="' + content[ 'type' ] + '" operation="' + \
          content[ 'op' ] + '">' + content[ 'value' ] + '</' + content[ 'name' ] + '>\n'

    xml = xml + \
          '  </' + type + '_' + variant + '>\n'
 
    return xml
