rule ESET_Kobalos_Ssh_Credential_Stealer {
  meta:
    description = "Kobalos SSH credential stealer seen in OpenSSH client"
    author      = "Marc-Etienne M.Léveillé"
    id          = "b1fc5163-de48-57fc-8ae7-1f2be6c64d8a"
    date        = "2020-11-02"
    modified    = "2021-02-01"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/kobalos/kobalos.yar#L58-L73"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    logic_hash  = "be238f5c2cc976a5638584a8c0fc580f2076735aadfe374e8d4162ba723bce10"
    score       = 75
    quality     = 80
    tags        = ""
    license     = "BSD 2-Clause"
    version     = "1"

  strings:
    $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

  condition:
    any of them
}