Sonatype IQ SBOM Scanner
A Python script to automate the submission and monitoring of Software Bill of Materials (SBOM) files to a Sonatype IQ Server for evaluation. The script scans a directory for CycloneDX XML files, uploads them using the REST API, and manages concurrent scans to avoid overloading the server.

Features
Bulk Submission: Ingests all .xml SBOM files from a specified directory.

Automatic Parsing: Extracts the applicationInternalId and stage from filenames.

Concurrency Control: Limits the number of simultaneous scans to a configurable maximum (default is 5).

Status Monitoring: Periodically checks the status of each scan and waits for completion before starting new ones.

Flexible Filename Handling: Correctly parses application names that contain underscores.

Detailed Error Reporting: Provides clear feedback on HTTP errors and server responses.

Prerequisites
Python 3.6+

The requests library.

You can install the necessary library using pip:

pip install requests

Filename Convention
The script expects the SBOM files to follow a specific naming convention to extract the necessary metadata for the API calls.

Format:
[application_name]_[stage]_[applicationInternalId].xml

application_name: The name of your application. It can contain underscores.

stage: The development lifecycle stage. Valid stages include build, develop, stage-release, release, operate, etc.

applicationInternalId: The unique internal identifier for the application in your Sonatype IQ Server.

Examples:

RPSService_source_a66930704fa94e019241d724d0ae2311.xml

user-microservice__volvogroupVG-MSCP_build_5ebc6dda22ac4885b3ef9227fd78da92.xml

Usage
Run the script from your command line, providing the path to your SBOMs directory, your Sonatype IQ Server URL, and your credentials.

Command-Line Arguments
-d, --directory: (Required) The working directory containing the SBOM .xml files.

-u, --user: (Required) Your Sonatype IQ Server username.

-p, --password: (Required) Your Sonatype IQ Server password.

-i, --url: (Required) The base URL of your Sonatype IQ Server (e.g., http://localhost:8070).

Example Command
python scansboms.py \
  --directory ./path/to/your/sboms \
  --user your_iq_username \
  --password your_iq_password \
  --url http://your-iq-server:8070

The script will then begin processing the files, providing real-time feedback on submissions and their status.
