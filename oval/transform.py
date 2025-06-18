import re


# version of each of the OVAL items which should rev when they change
transform_version = {
    'Definition' : "1",
    'Test'       : "1",
    'Object'     : "1",
    'State'      : "1"
}

def criterias( nvras, product, rl_version ) :
    """
    walk the nvras and create criterias which will be linked to
    tests, objects and states later in the processing chain
    """

    criterias = [ ]

    # check for base case test criteria which all criterias will have
    if product == "" :

        criterias.append( 
            {
                'operator' : "OR",
                'comment'  : "Rocky Linux must be installed",
                'id'       : "",
                'nested'   : True,
                'version'  : rl_version
            }
        )

        return criterias

    for nvra in nvras :

        # AND always has at least two items
        criterias.append(
            {
                'operator' : "AND",
                'comment'  : nvra,
                'id'       : "",
                'nested'   : False,
                'version'  : rl_version
            }
        )

        # continuation of an AND with necessary validation key
        criterias.append(
            {
                'operator' : "",
                'comment'  : nvra,
                'id'       : "",
                'nested'   : False,
                'version'  : rl_version
            }
        )

    # OR of the product installed (i.e. Rocky 8)
    criterias.append(
        {
            'operator' : "OR",
            'comment'  : product + " must be installed",
            'id'       : "",
            'nested'   : False,
            'version'  : rl_version
        }
    )
 
    return criterias


def references( cves, fixes, impact, public ) :
    """
    generate the references within a definition based on cves and fixes
    """

    # gather bug reports
    bugs = [ ]
    for fix in fixes :
        bugs.append( 
            {
                'cve'    : fix[ 'description' ].split( ' ' )[ 0 ],
                'source' : fix[ 'sourceBy' ], 
                'ref'    : fix[ 'sourceLink' ], 
                'id'     : fix[ 'ticket' ], 
                'desc'   : fix[ 'description' ] 
            }
        )

    # gather references
    references = [ ]
    for cve in cves :
        cve_id = cve[ 'name' ]
        references.append(
            { 
                'id'      : cve_id, 
                'url'     : cve[ 'sourceLink' ],
                'source'  : cve[ 'sourceBy' ],
                'cvss3'   : cve[ 'cvss3BaseScore' ] + cve[ 'cvss3ScoringVector' ],
                'cwe'     : cve[ 'cwe' ],
                'impact'  : impact,
                'public'  : public,
                'cve'     : cve_id
            }
        )

        # lookup bug for this cve (could be more efficient)
        for bug in bugs :
            if bug[ 'cve' ] == cve_id :
                references.append(
                    { 
                        'id'      : cve_id, 
                        'url'     : cve[ 'sourceLink' ],
                        'source'  : bug[ 'source' ],
                        'cvss3'   : cve[ 'cvss3BaseScore' ] + cve[ 'cvss3ScoringVector' ],
                        'cwe'     : cve[ 'cwe' ],
                        'impact'  : impact,
                        'public'  : public,
                        'cve'     : cve_id,
                        'bugref'  : bug[ 'ref' ],
                        'bugid'   : bug[ 'id' ],
                        'bugdesc' : bug[ 'desc' ]
                    }
                )
                break

    return references


def definitions( advisories, rl_version ) :
    """
    walk the list of advisories and generate definitions which contain
    metadata and criteria (the later of which are used to create tests)
    """

    definitions = [ ]
    version = 1

    # create up definitions based on advisories
    advisories.reset_index( )
    for _, advisory in advisories.iterrows( ) :

        # filtering out non-RLSA types (following addition of RXSA)
        if advisory[ 'name' ].split( '-' )[ 0 ] != "RLSA" :
            continue

        severity = advisory[ 'synopsis' ].split( ':' )[ 0 ]
        issued = advisory[ 'publishedAt' ].split( 'T' )[ 0 ]

        # create criterias
        crits = criterias( [ ], "", rl_version ) # base criteria for all Rocky Linux products
        for product in advisory[ 'affectedProducts' ] :
            crits = crits + criterias( advisory[ 'rpms.' + product + '.nvras' ], product, rl_version )

        description = \
            advisory[ 'description' ].replace( '\n', '\n\n' ) + \
            '\n\nSecurity Fix(es)\n\n'

        # create references
        refs = references( advisory[ 'cves' ], advisory[ 'fixes' ], severity.lower( ), issued.replace( '-', '' ) )
        for reference in refs :
            if 'bugdesc' in reference:
                id = reference[ 'bugdesc' ].split( ' ' )[ 0 ]
                desc = reference[ 'bugdesc' ].replace( id, '' )
                description = description + '*' + desc + '. (' + id + ')\n\n'

        # create definition
        definitions.append( 
            { 
                'id'          : advisory[ 'name' ].split( 'RLSA-' )[ 1 ].replace( ':', '' ), 
                'version'     : transform_version[ 'Definition' ],
                'title'       : advisory[ 'name' ] + ':'  + advisory[ 'synopsis' ].split( ':' )[ 1 ] + ' (' +  severity + ')',
                'severity'    : severity,
                'issued'      : issued,
                'updated'     : issued,
                'class'       : "patch", 
                'family'      : "unix",
                'platform'    : advisory[ 'affectedProducts' ],
                'description' : description,
                'ref_id'      : advisory[ 'name' ],
                'source'      : advisory[ 'name' ].split( '-' )[ 0 ],
                'references'  : refs,
                'cpes'        : [ "cpe:/a:rocky:linux:" + str( rl_version ) ],
                'criteria'    : crits
            }
        )
    
    return definitions

def generate_default( tests, objects, states, base_id, rl_version ) :

    # Rocky Linux check
    tests.append( 
        {
            'type'    : "rpmverifyfile",
            'id'      : base_id + str(len( tests ) + 1).zfill( 3 ),
            'version' : transform_version[ 'Test' ],
            'comment' : "Rocky Linux must be installed",
            'check'   : "none satisfy",
            'oid'     : base_id + str(len( objects ) + 1).zfill( 3 ),
            'sids'    : [ base_id + str(len( states ) + 1).zfill( 3 ) ]
        } 
    )

    # Add regex state here (rpmverifyfile_state)
    states.append(
       {
            'type'     : "rpmverifyfile",
            'id'       : base_id + str(len( states ) + 1).zfill( 3 ),
            'version'  : transform_version[ 'State' ],
            'product'  : "rockyrelease",
            'contents' : [ 
                { 
                    'name'      : "name",
                    'type'      : "", 
                    'operation' : "pattern match", 
                    'value'     : "^rocky-release" 
                }
            ]
        }
    )

    # Rocky Linux version check
    tests.append( 
        {
            'type'    : "rpmverifyfile",
            'id'      : base_id + str(len( tests ) + 1).zfill( 3 ),
            'version' : transform_version[ 'Test' ],
            'comment' : "Rocky Linux " + str( rl_version ) +" must be installed",
            'check'   : "at least one",
            'oid'     : base_id + str(len( objects ) + 1).zfill( 3 ),
            'sids'    : [ base_id + str(len( states ) + 1).zfill( 3 ) ]
        } 
    )

    # Add regex state here (rpmverifyfile_state)
    states.append(
        {
            'type'     : "rpmverifyfile",
            'id'       : base_id + str(len( states ) + 1).zfill( 3 ),
            'version'  : transform_version[ 'State' ],
            'product'  : "rockyrelease-" + str( rl_version ),
            'contents' : [ 
                { 
                    'name'      : "name",
                    'type'      : "",
                    'operation' : "pattern match", 
                    'value'     : "^rocky-release" 
                },
                { 
                    'name'      : "version",
                    'type'      : "", 
                    'operation' : "pattern match", 
                    'value'     : "^" + str( rl_version ) + "[^\d]" 
                }
            ]
        }
    )

    # Add regex object here (rpmverifyfile_object)
    objects.append(
        {
            'type'     : "rpmverifyfile",
            'id'       : base_id + str(len( objects ) + 1).zfill( 3 ),
            'version'  : transform_version[ 'Object' ],
            'contents' : [
                {
                    'name'      : "behaviors",
                    'pairs'     : [
                        { 'name' : "noconfigfiles", 'value' : "true" },
                        { 'name' : "noghostfiles", 'value' : "true" },
                        { 'name' : "nogroup", 'value' : "true" },
                        { 'name' : "nolinkto", 'value' : "true" },
                        { 'name' : "nomd5", 'value' : "true" },
                        { 'name' : "nomode", 'value' : "true" },
                        { 'name' : "nomtime", 'value' : "true" },
                        { 'name' : "nordev", 'value' : "true" },
                        { 'name' : "nosize", 'value' : "true" },
                        { 'name' : "nouser", 'value' : "true" }
                    ],
                    'operation' : "",
                    'value'     : ""
                },
                { 'name' : "name", 'pairs' : "", 'operation' : "pattern match", 'value' : "" },
                { 'name' : "epoch", 'pairs' : "", 'operation' : "pattern match", 'value' : "" },
                { 'name' : "version", 'pairs' : "", 'operation' : "pattern match", 'value' : "" },
                { 'name' : "release", 'pairs' : "", 'operation' : "pattern match", 'value' : "" },
                { 'name' : "arch", 'pairs' : "", 'operation' : "pattern match", 'value' : "" },
                { 'name' : "filepath", 'pairs': "", 'operation':"", 'value' : "/etc/rocky-release" }
            ]
        }
    )


def generate( definitions, rl_version ) :
    """
    walk through the criterias contained in the definitions and
    generate tests, objects and states for each case 
    """

    initialized = False

    tests = [ ]
    objects = [ ]
    states = [ ]

    # walk the definitions to create tests, objects and states
    for definition in definitions :

        base_id = definition[ 'id' ]

        # generate default base level content
        if len( tests ) == 0 :
            generate_default( tests, objects, states, base_id, rl_version )

        # walk the criterias to create additional tests, objects and states
        for criteria in definition[ 'criteria' ] :

            # decompose the evr components
            nevra = re.search( r"^(\S+)-(?:(\d)+:)([\w~%.+]+)-(\w+(?:\.[\w~%+]+)+?)(?:\.(\w+))?(?:\.rpm)?$", criteria[ 'comment' ] )
            if nevra :
                (product, epoch, version, release, platform) = nevra.groups( )
                evr = epoch + ':' + version + '-' + release
                
                # replace comment with message below
                if criteria[ 'operator' ] != "" :
                    criteria[ 'comment' ] = product + " is earlier than " + evr
                else :
                    criteria[ 'comment' ] = product + " is signed with Rocky Linux rockyrelease2 key"
                    criteria[ 'version' ] = evr

                # look for existing test
                tid = ""
                for test in tests :
                    if test[ 'comment' ] == criteria[ 'comment' ] :
                        tid = test[ 'id' ]
                        break

                # look for existing object
                oid = ""
                for object in objects :
                    for item in object[ 'contents' ] :
                        if item[ 'value' ] == product :
                            oid = object[ 'id' ]
                        break

                # look for existing state
                sid = ""
                for state in states :
                    if state[ 'product' ].split( ' ' )[ 0 ] == product :
                        sid = state[ 'id' ]
                        for item in state[ 'contents' ] :
                            if item[ 'name' ] == "evr" and item[ 'value' ] < evr :
                                item[ 'value' ] = evr
                        break

                # create new object if none was found
                if oid == "" :
                    oid = base_id + str(len( objects ) + 1).zfill( 3 )
                    objects.append(
                        {
                            'type'     : "rpminfo",
                            'id'       : oid,
                            'version'  : transform_version[ 'Object' ],
                            'contents' : [ 
                                { 
                                    'name'      : "name", 
                                    'pairs'     : "",
                                    'operation' : "", 
                                    'value'     : product 
                                } 
                            ] 
                        }
                    )

                # create new state if none was found
                if sid == "" :
                    sid = base_id + str(len( states ) + 1).zfill( 3 )
                    states.append(
                        {
                            'type'     : "rpminfo",
                            'id'       : sid,
                            'version'  : transform_version[ 'State' ],
                            'product'  : product,
                            'contents' : [
                                { 
                                    'name'      : "arch", 
                                    'type'      : "string", 
                                    'operation' : "pattern match",
                                    'value'     : platform
                                },
                                { 
                                    'name'      : "evr", 
                                    'type'      : "evr_string", 
                                    'operation' : "less than",
                                    'value'     : evr
                                }
                            ]
                        }
                    )
                        
                else :

                    # search for platform support and add if missing
                    for state in states :
                        for item in state[ 'contents' ] :
                            if item[ 'name' ] == "arch" :
                                found = False
                            
                                for arch in item[ 'value' ].split( '|' ) :
                                    if arch == platform :
                                        found = True
                                        break
                            
                                if found == False :
                                    item[ 'value' ] = item[ 'value' ] + "|" + platform

                # create test if none was found
                if tid == "" :
                    tid = base_id + str(len( tests ) + 1).zfill( 3 )
                    tests.append( 
                        {
                            'type'    : "rpminfo",
                            'id'      : tid,
                            'version' : transform_version[ 'Test' ],
                            'comment' : criteria[ 'comment' ],
                            'check'   : "at least one",
                            'oid'     : oid,
                            'sids'    : [ sid ]
                        } 
                    )
 
                criteria[ 'id' ] = tid

            else :
                # look for existing test
                tid = "unk"
                for test in tests :
                    if test[ 'comment' ] == criteria[ 'comment' ] :
                        tid = test[ 'id' ]
                        break

                criteria[ 'id' ] = tid

        # reduce to unique elements
        unique = [ ]
        for criteria in definition[ 'criteria' ] :
            if criteria in unique :
                continue
            else :
                unique.append( criteria )
        definition[ 'criteria' ] = unique

    return tests, objects, states
