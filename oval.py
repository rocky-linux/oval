import oval_xml as xml
import oval_control as ctrl

import sys

def output( definitions, tests, objects, states, rl_version ) :
    """
    output to OVAL XML content based on transformed content
    with definitions section followed by tests, objects, states
    """

    # header content
    print( xml.header( xml.version ) )

    # definitions section
    print( xml.section( "definitions") )
    for definition in definitions :

        metadata_output = xml.metadata(
            definition[ 'title' ], definition[ 'family' ], definition[ 'platform' ],
            definition[ 'ref_id' ], definition[ 'source' ], definition[ 'references' ], 
            definition[ 'description' ], definition[ 'severity' ], definition[ 'issued' ], 
            definition[ 'updated' ], definition[ 'cpes'], rl_version
        )

        criteria_output = xml.criteria( 
            xml.version[ "Scope" ], definition[ 'criteria' ]
        )

        # definition content
        print( xml.definition( xml.version[ "Scope" ], 
            definition[ 'id' ], definition[ 'version' ], definition[ 'class' ],
            metadata_output, criteria_output)
        )

    print( xml.section( "definitions", True ) )

    # tests section
    print( xml.section( "tests" ) )
    for test in tests :

        print( xml.test( xml.version[ 'Tag' ], xml.version[ "Scope" ],
            test[ 'type' ], test[ 'id' ], test[ 'version' ], test[ 'comment' ],
            test[ 'check' ], test[ 'oid' ], test[ 'sids' ] )
        )

    print( xml.section( "tests", True ) )

    # objects section
    print( xml.section( "objects" ) )
    for object in objects :

        print( xml.object( xml.version[ 'Tag' ], xml.version[ 'Scope' ],
            object[ 'type' ], object[ 'id' ], object[ 'version' ], 
            object[ 'contents' ] )
        )

    print( xml.section( "objects", True ) )

    # states section
    print( xml.section( "states" ) )
    for state in states :

        print( xml.state( xml.version[ 'Tag' ], xml.version[ 'Scope' ],
            state[ 'type' ], state[ 'id' ], state[ 'version' ], 
            state[ 'contents' ] )
        )

    print( xml.section( "states", True ) )

    # footer content
    print( xml.footer( ) )


def pipeline( rl_version ) :
    """
    pipeline for gathering advisories, normalizing and filtering followed
    by transforming and XML output
    """

    # ingest advisory information from API as list of JSON strings
    alist = ctrl.ingest( rl_version )

    # normalize JSON strings to dataframes
    advisories = ctrl.normalize( alist )

    # filter all advisories other than security type
    advisories = ctrl.filter( advisories )

    # transform to OVAL types
    definitions, tests, objects, states = ctrl.transform( advisories, rl_version )

    # output to OVAL XML content
    output( definitions, tests, objects, states, rl_version )


"""
TODO - remove dependency on pandas and use dictionary
TODO - add error handling to stderr
"""

def main( ):
    """
    run the pipeline to generate OVAL XML output based on current advisories
    """
    
    # get command line argument for version of rocky linux
    if len(sys.argv) > 1 :
        rl_version = int( sys.argv[1] )
    else :
        rl_version = 9

    # pipeline conversion from JSON ingest to OVAL XML output
    pipeline( rl_version )


if __name__ == "__main__":
    main( )
