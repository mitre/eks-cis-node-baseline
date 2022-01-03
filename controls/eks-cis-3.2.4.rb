control 'eks-cis-3.2.4' do
  title 'Ensure that the --read-only-port is secured'
  desc  'Disable the read-only port.'
  desc  'rationale', "The Kubelet process provides a read-only API in addition
to the main Kubelet API. Unauthenticated access is provided to this read-only
API which could possibly retrieve potentially sensitive information about the
cluster."
  desc  'check', "
    If using a Kubelet configuration file, check that there is an entry for
`authentication: anonymous: enabled` set to `0`.

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

    Verify that the `--read-only-port` argument exists and is set to `0`.

    If the `--read-only-port` argument is not present, check that there is a
Kubelet config file specified by `--config`. Check that if there is a
`readOnlyPort` entry in the file, it is set to `0`.
  "
  desc 'fix', "
    If modifying the Kubelet config file, edit the kubelet-config.json file
`/etc/kubernetes/kubelet/kubelet-config.json` and set the below parameter to
false

    ```
    readOnlyPort to 0
    ```

    If using executable arguments, edit the kubelet service file
`/etc/systemd/system/kubelet.service.d/10-kubelet-args.conf` on each worker
node and add the below parameter at the end of the `KUBELET_ARGS` variable
string.

    ```
    --read-only-port=0
    ```

    For all three remediations:
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
  tag nist: ['CM-7 (1)']
  tag cis_level: 1
  tag cis_controls: [
    { '6' => ['9.1'] },
    { '7' => ['9.2'] }
  ]
  tag cis_rid: '3.2.4'

  options = { assignment_regex: /(\S+)?=(\S+)?/ }
  service_flags = parse_config(service('kubelet').params['ExecStart'].gsub(' ', "\n"), options)

  describe.one do
    describe kubelet_config_file do
      its(['readOnlyPort']) { should be nil }
    end
    describe kubelet_config_file do
      its(['readOnlyPort']) { should be 0 }
    end
    describe 'Kubelet service flag' do
      subject { service_flags }
      its('--read-only-port') { should be nil }
    end
    describe 'Kubelet service flag' do
      subject { service_flags }
      its('--read-only-port') { should cmp '0' }
    end
  end
end
