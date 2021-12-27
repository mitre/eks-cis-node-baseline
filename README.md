# eks-cis-node-baseline

InSpec profile to validate the secure configuration of AWS EKS, against [CIS](https://www.cisecurity.org/cis-benchmarks/)'s CIS Amazon Elastic Kubernetes Service (EKS) Benchmark version 1.0.1.

## Getting Started

This profile should be executed from a runner host against each node comprising an EKS cluster in AWS using SSH. EKS nodes must be configured to accept an SSH connection from the runner host.

The profile may be downloaded to the runner for execution, or simply executed directly off of this GitHub repository. InSpec profiles can use different reporters to pressent output, such as the `cli` reporter to print results to the terminal and the `json` reporter to generate a JSON file of the results.

**For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# Used by check 3.2.3. Set this value to a string containing the full path
# ("/example/of/path/string/for/ca/file.crt")
# to the certificate authority file used for kubelet to authenticate certificates.
client_ca_file_path:

# Used by checks 3.2.10 and 3.2.11. Set this to `false` if your node kubelet processes
# get certificates from the k8s API server, or `true` if your certificates
# are handled by a process outside of k8s.
# Acceptable values (boolean): true false
external_cert_authority_in_use:
```

## Running the Profile

Executing the profile by downloading it to the runner:

```
git clone https://github.com/mitre/eks-cis-node-baseline.git
cd eks-cis-node-baseline
inspec exec . -t ssh://ec2-user@<node 1 IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:node1results.json
...
inspec exec . -t ssh://ec2-user@<node N IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:nodeNresults.json
```

Executing the profile by executing it from this GitHub repository:

```
inspec exec https://github.com/mitre/eks-cis-node-baseline/archive/main.tar.gz -t ssh://ec2-user@<node 1 IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:node1results.json
...
inspec exec https://github.com/mitre/eks-cis-node-baseline/archive/main.tar.gz -t ssh://ec2-user@<node N IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:nodeNresults.json
```

## Running This Baseline from a local Archive copy

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this profile and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/eks-cis-node-baseline.git
inspec archive eks-cis-node-baseline
sudo inspec exec <archive name> -t ssh://ec2-user@<node N IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:nodeNresults.json
```

For every successive run, follow these steps to always have the latest version of this baseline and dependent profiles:

```
cd eks-cis-node-baseline
git pull
cd ..
inspec archive eks-cis-node-baseline --overwrite
sudo inspec exec <archive name> -t ssh://ec2-user@<node N IP address> -i private_key.pem --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:nodeNresults.json
```

## Using Heimdall for Viewing the JSON Results

![Heimdall Lite 2.0 Demo GIF](https://github.com/mitre/heimdall2/blob/master/apps/frontend/public/heimdall-lite-2.0-demo-5fps.gif)

The JSON results output file can be loaded into **[heimdall-lite](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the InSpec results.

The JSON InSpec results file may also be loaded into a **[full heimdall server](https://github.com/mitre/heimdall)**, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors

- Will Dower - [wdower](https://github.com/wdower)

## Special Thanks

- Rony Xavier - [rx294](https://github.com/rx294)

## Contributing and Getting Help

To report a bug or feature request, please open an [issue](https://github.com/mitre/eks-cis-node-baseline/issues/new).

### NOTICE

© 2018-2021 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

## NOTICE

CIS Benchmarks are published by the Center for Internet Security (CIS), see: https://www.cisecurity.org/cis-benchmarks/.
