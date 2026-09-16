rule blake2b_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89c39ca284190a1351ee8acf1166c7afd3cfd9461235cd8f2a9bcf0916f7d58ed61b373b384f5fe6ecd600b214010689c56be2ab4c91dc5ce5a11b87a1bc52b6"
    $a1="89c39ca284190a1351ee8acf1166c7afd3cfd9461235cd8f2a9bcf0916f7d58ed61b373b384f5fe6ecd600b214010689c56be2ab4c91dc5ce5a11b87a1bc52b6"
    $a2="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}