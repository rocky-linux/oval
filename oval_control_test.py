import oval_control as oval


def unit_test_ingest( ) :

    alist = oval.ingest( )

    return alist


def unit_test_normalize( alist ) :

    advisories = oval.normalize( alist )

    return advisories


def unit_test_filter( advisories ) :

    advisories = oval.filter( advisories )

    return advisories


def unit_test_transform( advisories ) :

    definitions, tests, objects, states = oval.transform( advisories )

    return definitions, tests, objects, states


def unit_test( ) :

    seperate = '\n--------------------------------\n'

    alist = unit_test_ingest( )
    ctrl = str( alist ) + seperate
 
    advisories = unit_test_normalize( alist )
    ctrl = ctrl + str( advisories ) + seperate

    advisories = unit_test_filter( advisories )
    ctrl = ctrl + str( advisories ) + seperate

    for advisory in advisories :
        ctrl = ctrl + str( advisories[ advisory ] )
    ctrl = ctrl + seperate
    
    definitions, tests, objects, states = unit_test_transform( advisories )
    ctrl = ctrl + str( definitions ) + str( tests ) + str( objects ) + str( states )

    return ctrl


def main( ):

    print( unit_test() )


if __name__ == "__main__":
    main()
