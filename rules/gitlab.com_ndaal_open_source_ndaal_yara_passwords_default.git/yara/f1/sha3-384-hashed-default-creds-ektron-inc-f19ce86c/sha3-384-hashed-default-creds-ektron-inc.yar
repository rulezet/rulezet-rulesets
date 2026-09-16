rule sha3_384_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf45272818041e47979f7b30b6e4b88161efa400807adc045f15f262bb94956fd31208ce50ab332735c7edd1c006d7fa"
    $a1="bf45272818041e47979f7b30b6e4b88161efa400807adc045f15f262bb94956fd31208ce50ab332735c7edd1c006d7fa"
    $a2="43a121eba75b3bc0e26ab1dc8069251ae7257b535727b73a89a039192151787ca848a529679cac9eb69b7589f32343cf"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}