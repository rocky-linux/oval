"""
OVAL Control

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

import requests as rq
import pandas as pd

from oval import transform as xfrm

# base API for gathering advisories
BASEAPI = "https://apollo.build.resf.org/v2"
BASEFILTER = "/advisories?filters.type=TYPE_SECURITY&filters.includeRpms=true"

# used to limit the total advisories for testing
PAGE_LIMIT = 2000
PER_RQ_LIMIT = 100
PER_RQ_TIMEOUT = 2000 # ms

def ingest( rl_version ) :
    """
    ingest advisories from API as list of JSON strings
    """

    alist = []
    page = 0
    while True:
        product_filter = f"&filters.product=Rocky%20Linux%20{rl_version}"
        url = f"{BASEAPI}{BASEFILTER}{product_filter}&page={page}&limit={PER_RQ_LIMIT}"

        advisory_items = rq.get(url, timeout=PER_RQ_TIMEOUT).json()

        if not advisory_items['advisories'] or page > PAGE_LIMIT:
            break

        for advisory_item in advisory_items['advisories']:
            url = f"{BASEAPI}/advisories/{advisory_item['name']}"
            advisory = rq.get(url, timeout=PER_RQ_TIMEOUT).json()
            alist.append(advisory)

        page += 1
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

    return advisories[ advisories[ 'type' ] == "TYPE_SECURITY" ]



def transform( advisories, rl_version ) :
    """
    transform advisories into definitions, tests, objects and states
    """

    # create a high-level definition for each advisory
    definitions = xfrm.definitions( advisories, rl_version )

    # generate tests, objects and states from each high-level definition
    tests, objects, states = xfrm.generate( definitions, rl_version )

    return definitions, tests, objects, states
