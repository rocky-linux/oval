import oval_xml as oval


def unit_test_header( ) :
    xml = oval.header( oval.version )
    return xml     


def unit_test_definitions( ) :
    metadata_output = oval.metadata(
        "Rocky 8 is installed on the endpoint", "rocky8", 
        [ "Rocky 8.4", "Rocky 8.5", "Rocky 8.6" ], "RLSA-2022:3030", "RLSA",
        [ { 'id' : "RLSA-2022:3030", 'url' : "https://access.rockylinux.org/errata/RLSA-2022:3030", 
            'source' : "RLSA", 'cvss3' : "CVSS3", 'cwe' : "CWE", 'impact' : "moderate", 'public'  : "20220902",
            'cve' : "CVE", 'bugref'  : "https://bugzilla.rockylinux.org/", 'bugid' : "spider",
            'bugdesc' : "creepy crawly" } ], "Look whose crawling on the floor", "Moderate", 
            "2022-10-31T17:03:05", "2022-10-31T17:03:06", [ "cpe:/a:rockylinux:enterprise_linux:8" ]
    )
    criteria_output = oval.criteria( 
        oval.version[ "Scope" ], [
            { 'operator' : "OR", 'comment' : "Rocky Linux is installed",  'id' : "1", 'nested' : True },
            { 'operator' : "AND",'comment' : "Rocky 8 version 8.5 is installed",  'id' : "2", 'nested' : False },
            { 'operator' : "OR",'comment' : "Rocky 8 version 8.6 is installed",  'id' : "3", 'nested' : False }
        ]
    )
    xml = oval.section( "definitions")
    xml = xml + oval.definition( 
        oval.version[ "Scope" ], "123", "1", "inventory", metadata_output, criteria_output
    )    
    xml = xml + oval.section( "definitions", True )
    return xml


def unit_test_tests( ) :
    xml = oval.section( "tests")
    xml = xml + oval.test( 
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "1", "4", "Rocky 8 version 1.0 is installed",
        "at_least_one_exists", "1", [ "1" ]
    )    
    xml = xml + oval.test(
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "2", "2", "Rocky 8 version 1.5 is installed",
        "at_least_one_exists", "2", [ "2" ]
    )
    xml = xml + oval.section( "tests", True )
    return xml


def unit_test_objects( ) :
    xml = oval.section( "objects" )
    xml = xml + oval.object( 
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "1", "3", 
        [ { 'name' : "name", 'pairs' : "", 'operation' : "", 'value' : "Version" } ]
    )
    xml = xml + oval.object( 
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "2", "2", 
        [ { 'name' : "name", 'pairs' : "", 'operation' : "", 'value' : "Version" } ]
    )
    xml = xml + oval.set(
        oval.version[ "Scope" ], "file", "55", "1", "#unix", "UNION",
        [ "33", "44" ]
    )
    xml = xml + oval.filter(
        oval.version[ "Scope" ], "file", "66", "1", "#unix",
        [ { 'name' : "path", 'op' : "pattern match", 'value' : "." },
          { 'name' : "filename", 'op' : "pattern match", 'value' : "." } ],
        "include", "55"
    )
    xml = xml + oval.section( "objects", True )
    return xml


def unit_test_states( ) :
    xml = oval.section( "states" )
    xml = xml + oval.state(
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "1", "2", 
        [ { 'name' : "value", 'type' : "", 'operation' : "", 'value' : "1.0" } ]
    )
    xml = xml + oval.state( 
        oval.version[ "Tag" ], oval.version[ "Scope" ], "kernel", "2", "2", 
        [ { 'name' : "value", 'type' : "", 'operation' : "", 'value' : "1.5" } ]
    )
    xml = xml + oval.variable(
        oval.version[ "Scope" ], "constant", "2", "3", "string",
        "The kernel module matches with the version specified below",
        [ "1.0", "1.2", "1.3" ]
    )
    xml = xml + oval.regex( 
        oval.version[ "Scope" ], "state", "kernel", "2", "2", 
        "The kernel module matches with the version of Rocky 8.6",
        "#linux", [ { 'name' : "value", 'type' : "string", 'op' : "pattern match", 'value' : "." } ]
    )
    xml = xml + oval.section( "states", True )
    return xml


def unit_test_regexs( ) :
    return ""


def unit_test_footer( ) :
    xml = oval.footer( )
    return xml


def unit_test( ) :
    return \
        unit_test_header( ) + \
        unit_test_definitions( ) + \
        unit_test_tests( ) + \
        unit_test_objects( ) + \
        unit_test_states( ) + \
        unit_test_footer( )


def main( ):

    print( unit_test( ) )


if __name__ == "__main__":
    main()