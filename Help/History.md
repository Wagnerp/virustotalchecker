# History #

**v1.0.5**

- Modified to store and output the result of the Microsoft (Security Essentials) scan
 
**v1.0.4**

- Updated the config file to be SQL CE aware

**v1.0.3**

- Added Permalink, Response and Scan Date fields to the database (VirusTotal.Net library)
- Added the ability to import a JSON file that is produced from a virustotal-search pickle file. You need to run the supplied convert-pickle-to-json.py. The python script expects the input file to be called “virustotal-search.pkl”, the output file will be “virustotal-search.json”
- Fixed bug which cause an error if the resource could not be found on VT
- Added SHA256 support e.g. it stores it and you can search on it
- Removed the need to specify the hash type, now it just looks at the length e.g. 32 or 64 characters

**v1.0.2**

- Modified to allow for just live results
- Modified to update reports with 0/0 results
- Improved output for failed (0/0) results
- Updated the command line parameters to allow the user to select the database path


**v1.0.1**

- Initial public release