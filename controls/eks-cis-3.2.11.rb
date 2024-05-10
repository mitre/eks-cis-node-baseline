control 'eks-cis-3.2.11' do
  title "Ensure that the RotateKubeletServerCertificate argument is set
  to true"
  desc  'Enable kubelet server certificate rotation.'
  desc  'rationale', "
    `RotateKubeletServerCertificate` causes the kubelet to both request a
serving certificate after bootstrapping its client credentials and rotate the
certificate as its existing credentials expire. This automated periodic
rotation ensures that the there are no downtimes due to expired certificates
and thus addressing availability in the CIA security triad.

    Note: This recommendation only applies if you let kubelets get their
certificates from the API server. In case your kubelet certificates come from
an outside authority/tool (e.g. Vault) then you need to take care of rotation
yourself.
  "
  desc 'check', "
    **Audit Method 1:**

    If using a Kubelet configuration file, check that there is an entry for
`RotateKubeletServerCertificate` is set to `true`.

    First, SSH to the relevant node:

    Run the following command on each node to find the appropriate Kubelet
config file:

    ```
    ps -ef | grep kubelet
    ```
    The output of the above command should return something similar to
`--config /etc/kubernetes/kubelet/kubelet-config.json` which is the location of
the Kubelet config file.

    Open the Kubelet config file:
    ```
    cat /etc/kubernetes/kubelet/kubelet-config.json
    ```

    Verify that `RotateKubeletServerCertificate` argument exists and is set to
`true`.

    **Audit Method 2:**

    If using the api configz endpoint consider searching for the status of
`\"RotateKubeletServerCertificate\":true` by extracting the live configuration
from the nodes running kubelet.

    Set the local proxy port and the following variables and provide proxy port
number and node name;
    `HOSTNAME_PORT=\"localhost-and-port-number\"`
    `NODE_NAME=\"The-Name-Of-Node-To-Extract-Configuration\" from the output of
\"kubectl get nodes\"`
    ```
    kubectl proxy --port=8001 &

    export HOSTNAME_PORT=localhost:8001 (example host and port number)
    export NODE_NAME=ip-192.168.31.226.ec2.internal (example node name from
\"kubectl get nodes\")

    curl -sSL
\"http://${HOSTNAME_PORT}/api/v1/nodes/${NODE_NAME}/proxy/configz\"
    ```
  "
  desc 'fix', "
    **Remediation Method 1:**

    If modifying the Kubelet config file, edit the kubelet-config.json file
`/etc/kubernetes/kubelet/kubelet-config.json` and set the below parameter to
true

    ```
    \"RotateKubeletServerCertificate\":true
    ```

    **Remediation Method 2:**

    If using a Kubelet config file, edit the file to set
`RotateKubeletServerCertificate to true`.

    If using executable arguments, edit the kubelet service file
`/etc/systemd/system/kubelet.service.d/10-kubelet-args.conf` on each worker
node and add the below parameter at the end of the `KUBELET_ARGS` variable
string.

    ```
    --rotate-kubelet-server-certificate=true
    ```

    **Remediation Method 3:**

    If using the api configz endpoint consider searching for the status of
`\"RotateKubeletServerCertificate\":` by extracting the live configuration from
the nodes running kubelet.

    **See detailed step-by-step configmap procedures in [Reconfigure a Node's
Kubelet in a Live
Cluster](https://kubernetes.io/docs/tasks/administer-cluster/reconfigure-kubelet/),
and then rerun the curl statement from audit process to check for kubelet
configuration changes
    ```
    kubectl proxy --port=8001 &

    export HOSTNAME_PORT=localhost:8001 (example host and port number)
    export NODE_NAME=ip-192.168.31.226.ec2.internal (example node name from
\"kubectl get nodes\")

    curl -sSL
\"http://${HOSTNAME_PORT}/api/v1/nodes/${NODE_NAME}/proxy/configz\"
    ```

    **For all three remediations:**
    Based on your system, restart the `kubelet` service and check status

    ```
    systemctl daemon-reload
    systemctl restart kubelet.service
    systemctl status kubelet -l
    ```
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['SC-8']
  tag cis_level: 1
  tag cis_controls: [
    { '6' => ['14.2'] },
    { '7' => ['14.4'] }
  ]
  tag cis_rid: '3.2.11'

  external_cert_authority_in_use = input('external_cert_authority_in_use')

  options = { assignment_regex: /(\S+)?:(\S+)?/ }
  service_flags = parse_config(service('kubelet').params['ExecStart'].gsub(' ', "\n"), options)

  if external_cert_authority_in_use
    describe 'N/A - Node using external authority/tool to handle certificate rotation' do
      skip 'N/A - Node using external authority/tool to handle certificate rotation'
    end
  else
    describe.one do
      describe kubelet_config_file do
        its(['featureGates','RotateKubeletServerCertificate']) { should be true }
      end
      describe 'Kubelet service flag' do
        subject { service_flags }
        its('--rotate-kubelet-server-certificate') { should cmp 'true' }
      end
    end
  end
end
