# encoding: UTF-8

control 'eks-cis-3.2.3' do
  title "Ensure that the --client-ca-file argument is set as appropriate"
  desc  'Enable Kubelet authentication using certificates.'
  desc  'rationale', "The connections from the apiserver to the kubelet are
used for fetching logs for pods, attaching (through kubectl) to running pods,
and using the kubelet’s port-forwarding functionality. These connections
terminate at the kubelet’s HTTPS endpoint. By default, the apiserver does not
verify the kubelet’s serving certificate, which makes the connection subject to
man-in-the-middle attacks, and unsafe to run over untrusted and/or public
networks. Enabling Kubelet certificate authentication ensures that the
apiserver could authenticate the Kubelet before submitting any requests."
  desc  'check', "
    **Audit Method 1:**

    If using a Kubelet configuration file, check that there is an entry for
`\"x509\": {\"clientCAFile:\"` set to the location of the client certificate
authority file.

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
    sudo more /etc/kubernetes/kubelet/kubelet-config.json
    ```

    Verify that the `\"x509\": {\"clientCAFile:\"` argument exists and is set
to the location of the client certificate authority file.

    If the `\"x509\": {\"clientCAFile:\"` argument is not present, check that
there is a Kubelet config file specified by `--config`, and that the file sets
`\"authentication\": { \"x509\": {\"clientCAFile:\"` to the location of the
client certificate authority file.

    **Audit Method 2:**

    If using the api configz endpoint consider searching for the status of
`authentication.. x509\":(\"clientCAFile\":\"/etc/kubernetes/pki/ca.crt` by
extracting the live configuration from the nodes running kubelet.

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
  desc  'fix', "
    **Remediation Method 1:**

    If modifying the Kubelet config file, edit the kubelet-config.json file
`/etc/kubernetes/kubelet/kubelet-config.json` and set the below parameter to
false

    ```
    \"authentication\": { \"x509\": {\"clientCAFile:\" to the location of the
client CA file.
    ```

    **Remediation Method 2:**

    If using executable arguments, edit the kubelet service file
`/etc/systemd/system/kubelet.service.d/10-kubelet-args.conf` on each worker
node and add the below parameter at the end of the `KUBELET_ARGS` variable
string.

    ```
    --client-ca-file=<path/to/client-ca-file>
    ```

    **Remediation Method 3:**

    If using the api configz endpoint consider searching for the status of
`\"authentication.*x509\":(\"clientCAFile\":\"/etc/kubernetes/pki/ca.crt\"` by
extracting the live configuration from the nodes running kubelet.

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
  tag nist: ['AC-4', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['14.2', 'Rev_6']
  tag cis_rid: '3.2.3'

  kubelet_config_file = input('kubelet_config')

  node_name = input('node_name')
  proxy_hostname = input('proxy_hostname')
  proxy_port = input('proxy_port')

  client_ca_file_path = input('client_ca_file_path')

  kubelet_config_accessible_via_api = !node_name.empty? && !proxy_hostname.empty? && !proxy_port.empty?

  if !kubelet_config_file.empty?
    kubelet_config_extension = File.extname(kubelet_config_file)
    if kubelet_config_extension == '.json'
      describe json(kubelet_config_file) do
        its(['authentication', 'x509', 'clientCAFile']) { should cmp client_ca_file_path }
      end
    elsif kubelet_config_extension == '.yaml' || kubelet_config_extension == '.yml'
      describe yaml(kubelet_config_file) do
        its(['authentication', 'x509', 'clientCAFile']) { should cmp client_ca_file_path }
      end
    else
      describe "kubelet config file error -- format" do
        subject{ kubelet_config_extension }
        it { should be_in ['.yaml', '.yml', '.json'] }
      end
    end
  elsif kubelet_config_accessible_via_api
    describe "Checking /configz kubelet API endpoint for kubelet config data" do
      subject { json(content: http("http://#{proxy_hostname}:#{proxy_port}/api/v1/nodes/#{node_name}/proxy/configz").body) }
      its(['kubeletconfig', 'authentication', 'x509', 'clientCAFile']) { should cmp client_ca_file_path }
    end
  else
    describe "There should be inputs given on how to find kubelet config data" do
      subject { !kubelet_config_file.empty? || kubelet_config_accessible_via_api }
      it { should be true }
    end
  end
end

