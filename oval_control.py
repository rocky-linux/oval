import oval_transform as xfrm
import requests as rq
import pandas as pd

"""
An advisory record has the following structure:
	type                     str
	shortCode                str
	name                     str
	synopsis                 str
	severity                 str
	topic                    str
	description              str
	solution                 str
	affectedProducts         []str
	fixes                    []str
	cves                     []str
	references               str
	publishedAt              str
	rebootSuggested          str
	rpms_Rocky_Linux_8_nvras []str
"""

# base API for gathering advisories
baseapi = "https://apollo.build.resf.org/v2"
basefilter = "/advisories?filters.type=TYPE_SECURITY&filters.includeRpms=true"

# used to limit the total advisories for testing
page_limit = 2000
per_rq_limit = 100

def ingest( ) :
    """
    ingest advisories from API as list of JSON strings
    """

    alist = [ ]

    page = 1
    while True :

        advisory_items = rq.get( baseapi + basefilter + "&page=" + \
            str( page ) + "&limit=" + str( per_rq_limit ) ).json( )
        if advisory_items[ 'advisories' ] == [ ] or page > page_limit :
            break
 
        for a in advisory_items.get( "advisories" ) :
            advisory = rq.get( baseapi + "/advisories/" + a.get( "name" ) ).json( )
            alist.append( advisory )

        page = page + 1

    return alist


def normalize( alist ) :
    """
    normalize list of JSON strings to dataframes
    """

    advisories = pd.DataFrame( )

    for a in alist :

        # flatten the list
        advisory = pd.json_normalize( a['advisory'] )

        # add to dataframe        
        advisories = pd.concat( [ advisories, advisory ], ignore_index = True )

    return advisories


def filter( advisories ) :
    """
    filter all advisories from a dataframe other than security type
    """

    return advisories[ advisories[ 'type' ] == 'TYPE_SECURITY' ]


def transform( advisories ) :
    """
    transform advisories into definitions, tests, objects and states
    """

    # create a high-level definition for each advisory
    definitions = xfrm.definitions( advisories )

    # generate tests, objects and states from each high-level definition
    tests, objects, states = xfrm.generate( definitions )

    return definitions, tests, objects, states
