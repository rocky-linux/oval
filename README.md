# OvalPy

ETL script for extracting security advisories, transforming content, and exporting it to OVAL compliant XML.

# Structure

* oval.py - `Main ETL script for initiating pipeline`
* oval_control.py - `Control for gathering and normalizing`
* oval_transform.py - `Transformation and generation of types`
* oval_xml.py - `XML formated output of types`

# Dependencies

Python3 with Pandas module support

`dnf install python3`

`python3 -m pip install pandas`

# Running the script

`python3 oval.py > oval.xml`
