control 'eks-cis-3.2.10' do
  title 'Ensure that the --rotate-certificates argument is not set to false'
  desc  'Enable kubelet client certificate rotation.'
  desc  'rationale', "
    The `--rotate-certificates` setting causes the kubelet to rotate its client
certificates by creating new CSRs as its existing credentials expire. This
automated periodic rotation ensures that the there is no downtime due to
expired certificates and thus addressing availability in the CIA security triad.

    **Note:** This recommendation only applies if you let kubelets get their
certificates from the API server. In case your kubelet certificates come from
an outside authority/tool (e.g. Vault) then you need to take care of rotation
yourself.

    **Note:** This feature also require the `RotateKubeletClientCertificate`
feature gate to be enabled (which is the default since Kubernetes v1.7)
  "
  desc 'check', "
    **Audit Method 1:**

    If using a Kubelet configuration file, check that there is an entry for
`--rotate-certificates` set to `false`.

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

    Verify that the `RotateCertificate` argument is not present, or is set to
`true`.

    If the `--rotate-certificates` argument is not present, verify that if
there is a Kubelet config file specified by `--config`, that file does not
contain `rotateCertificates: false`.
  "
  desc 'fix', "
    **Remediation Method 1:**

    If modifying the Kubelet config file, edit the kubelet-config.json file
`/etc/kubernetes/kubelet/kubelet-config.json` and set the below parameter to
false

    ```
    \"RotateCertificate\":true
    ```

    **Remediation Method 2:**

    If using executable arguments, edit the kubelet service file
`/etc/systemd/system/kubelet.service.d/10-kubelet-args.conf` on each worker
node and add the below parameter at the end of the `KUBELET_ARGS` variable
string.

    ```
    --RotateCertificate=true
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
  tag cis_level: 2
  tag cis_controls: [
    { '6' => ['14.2'] },
    { '7' => ['14.4'] }
  ]
  tag cis_rid: '3.2.10'

  external_cert_authority_in_use = input('external_cert_authority_in_use')

  options = { assignment_regex: /(\S+)?:(\S+)?/ }
  service_flags = parse_config(service('kubelet').params['ExecStart'].gsub(' ', "\n"), options)

  if external_cert_authority_in_use
    describe 'N/A - Node using external authority/tool to handle certificate rotation' do
      skip 'N/A - Node using external authority/tool to handle certificate rotation'
    end
  else
    describe.one do
      describe kubelet_config_file  do
        its(['rotateCertificates']) { should_not be false }
      end
      describe 'Kubelet service flag' do
        subject { service_flags }
        its('--rotate-certificates') { should cmp 'false' }
      end
    end
  end
end
