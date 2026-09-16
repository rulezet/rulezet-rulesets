rule kimwolf_proxy
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - C/C++ variants with ENS C2 (Gen 1-3)"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "7592efd1-8805-4ca1-8e2f-f01da1a30d01"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "036bcb62be72c4663b9564955f93b05f"

    strings:
                $rpc_0xrpc = "0xrpc.io/eth"
        $rpc_llama = "eth.llamarpc.com"
        $rpc_publicnode = "ethereum-rpc.publicnode.com"
        $rpc_blxrbdn = "eth-protect.rpc.blxrbdn.com"
        $rpc_merkle = "eth.merkle.io"
        $rpc_payload = "rpc.payload.de"
        $rpc_flashbots = "rpc.flashbots.net"

                $ens_resolver = { 01 78 b8 bf }
        $ens_text = { 59 d1 d4 3c }

                $eth_call = "eth_call"

                $netd_service = "netd_service"

                $stun = "stun.cloudflare.com"

                $rtti_proxy = "ProxySession"
        $rtti_ddos = "NiggerTransferProtocolSession"

                $socks5 = "SOCKS5: connecting to HTTP proxy"
        $cpool = "[CPOOL]"

                $path_sylvia = "/home/SylviaFennec/AbcProxySDK/"
        $path_proxy_client = "/home/user/proxy-client/"

    condition:
        uint32(0) == 0x464c457f and
                (3 of ($rpc_*) or $ens_resolver or $ens_text or $eth_call) and
        (
                        (($ens_resolver or $ens_text) and 3 of ($rpc_*)) or

                        (($path_sylvia or $path_proxy_client) and ($socks5 or $cpool)) or

                        (($rtti_ddos or $rtti_proxy) and $eth_call) or

                        ($socks5 and $netd_service and $stun and $eth_call) or

                        (3 of ($rpc_*) and $netd_service and ($socks5 or $cpool))
        )
}