"""
ETL script for extracting security advisories, transforming content,
and exporting it to OVAL compliant XML.
"""
import sys
import argparse

from oval import control as ctrl
from oval import xml


def output(definitions, tests, objects, states, rl_version):
    """
    output to OVAL XML content based on transformed content
    with definitions section followed by tests, objects, states
    """

    # header content
    print(xml.header(xml.version))

    # definitions section
    print(xml.section("definitions"))
    for definition in definitions:
        metadata_output = xml.metadata(
            definition["title"],
            definition["family"],
            definition["platform"],
            definition["ref_id"],
            definition["source"],
            definition["references"],
            definition["description"],
            definition["severity"],
            definition["issued"],
            definition["updated"],
            definition["cpes"],
            rl_version,
        )

        criteria_output = xml.criteria(xml.version["Scope"], definition["criteria"])

        # definition content
        print(
            xml.definition(
                xml.version["Scope"],
                definition["id"],
                definition["version"],
                definition["class"],
                metadata_output,
                criteria_output,
            )
        )

    print(xml.section("definitions", True))

    # tests section
    print(xml.section("tests"))
    for test in tests:
        print(
            xml.test(
                xml.version["Tag"],
                xml.version["Scope"],
                test["type"],
                test["id"],
                test["version"],
                test["comment"],
                test["check"],
                test["oid"],
                test["sids"],
            )
        )

    print(xml.section("tests", True))

    # objects section
    print(xml.section("objects"))
    for obj in objects:
        print(
            xml.object(
                xml.version["Tag"],
                xml.version["Scope"],
                obj["type"],
                obj["id"],
                obj["version"],
                obj["contents"],
            )
        )

    print(xml.section("objects", True))

    # states section
    print(xml.section("states"))
    for state in states:
        print(
            xml.state(
                xml.version["Tag"],
                xml.version["Scope"],
                state["type"],
                state["id"],
                state["version"],
                state["contents"],
            )
        )

    print(xml.section("states", True))

    # footer content
    print(xml.footer())


def pipeline(rl_version, sa_type):
    """
    pipeline for gathering advisories, normalizing and filtering followed
    by transforming and XML output
    """

    # ingest advisory information from API as list of JSON strings
    alist = ctrl.ingest(rl_version)

    # normalize JSON strings to dataframes
    advisories = ctrl.normalize(alist)

    # filter all advisories other than security type
    advisories = ctrl.filter(advisories)

    # transform to OVAL types
    definitions, tests, objects, states = ctrl.transform(advisories, rl_version, sa_type)

    # output to OVAL XML content
    output(definitions, tests, objects, states, rl_version)


def main():
    """
    run the pipeline to generate OVAL XML output based on current advisories

    @TODO - remove dependency on pandas and use dictionary
    @TODO - add error handling to stderr
    """

    # get command line arguments for version of rocky linux and security advisory type
    parser = argparse.ArgumentParser(description='Configuration parameters')
    parser.add_argument('--rl_version', type=int, required=False, default=9, help='rocky linux version')
    parser.add_argument('--sa_type', type=str, required=False, default='RLSA', help='security advisory type')
    args = parser.parse_args()

    # pipeline conversion from JSON ingest to OVAL XML output
    pipeline(args.rl_version, args.sa_type)


if __name__ == "__main__":
    main()
