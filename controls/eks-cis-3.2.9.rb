control 'eks-cis-3.2.9' do
  title "Ensure that the --eventRecordQPS argument is set to 0 or a level
  which ensures appropriate event capture"
  desc  "Security relevant information should be captured. The
`--eventRecordQPS` flag on the Kubelet can be used to limit the rate at which
events are gathered. Setting this too low could result in relevant events not
being logged, however the unlimited setting of `0` could result in a denial of
service on the kubelet."
  desc  'rationale', "It is important to capture all events and not restrict
event creation. Events are an important source of security information and
analytics that ensure that your environment is consistently monitored using the
event data."
  desc  'check', "
    **Audit Method 1:**

    If using a Kubelet configuration file, check that there is an entry for
`eventRecordQPS` set to `5` or a value equal to or greater than 0.

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

    Review the value set for the `--eventRecordQPS` argument and determine
whether this has been set to an appropriate level for the cluster. The value of
`0` can be used to ensure that all events are captured.

    If the `--eventRecordQPS` argument does not exist, check that there is a
Kubelet config file specified by `--config` and review the value in this
location.

    **Audit Method 2:**

    If using the api configz endpoint consider searching for the status of
`eventRecordQPS` by extracting the live configuration from the nodes running
kubelet.

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
`/etc/kubernetes/kubelet/kubelet-config.json` and set the below parameter to 5
or a value greater or equal to 0

    ```
    \"eventRecordQPS\": 5
    ```

    **Remediation Method 2:**

    If using executable arguments, edit the kubelet service file
`/etc/systemd/system/kubelet.service.d/10-kubelet-args.conf` on each worker
node and add the below parameter at the end of the `KUBELET_ARGS` variable
string.

    ```
    --eventRecordQPS=5
    ```

    **Remediation Method 3:**

    If using the api configz endpoint consider searching for the status of
`\"eventRecordQPS\"` by extracting the live configuration from the nodes
running kubelet.

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
  tag nist: ['AU-6']
  tag cis_level: 2
  tag cis_controls: [
    { '6' => ['6'] },
    { '7' => ['6'] }
  ]
  tag cis_rid: '3.2.9'

  options = { assignment_regex: /(\S+)?:(\S+)?/ }
  service_flags = parse_config(service('kubelet').params['ExecStart'].gsub(' ', "\n"), options)

  describe.one do
    describe kubelet_config_file do
      its(['eventRecordQPS']) { should be >= 0 }
    end
    describe 'Kubelet service flag' do
      subject { service_flags }
      its('--eventRecordQPS') { should_not be nil }
      its('--eventRecordQPS.to_i') { should be >= 0 }
    end
  end
end
