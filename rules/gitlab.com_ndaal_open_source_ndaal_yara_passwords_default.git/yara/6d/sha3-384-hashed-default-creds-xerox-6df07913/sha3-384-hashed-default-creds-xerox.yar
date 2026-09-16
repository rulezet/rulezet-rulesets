rule sha3_384_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aec075258ad7a6fe83b0453b94dd216ec951ae6545ea701dc1c76c9a233d6aadeabd4add0e992f86d0025acf30880379"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="6bdc1b784f4a65070782b0168fe535716083235d6de618c10a913145b5d78669e7565a1cdaba90a417d4641d95dc02c0"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="8857455b879a24793921ec64736a5eb978e9ce9e6a47c73fe7a8e15420370a713e20b3d1e8e115f0284302c3c46263f3"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="aec075258ad7a6fe83b0453b94dd216ec951ae6545ea701dc1c76c9a233d6aadeabd4add0e992f86d0025acf30880379"
    $a9="644dd0adc6062a0cec429a7b3b8a4f79c2575cc65ed9ffc7511bf73b372e8226e3ef3a0f659f9c1e166c0ccbe66b4f56"
    $a10="2e4348136442e08ecf7a1656b5ad070d095716ad847b6f739e697212992bce735f774f735608746a3cecfb20f616a9ef"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="e1e616c25b1593ceb17e42259fc284ce80bf053500c82ebea7f864320ca06a480afe552f5d3aa3c55192ebc9d156a8f6"
    $a13="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a14="ad6dc23b401f000f5bbbf52a042f23570d0159934484c027a92d896851d391fef350e45ae50f72d6386647c670c32136"
    $a15="7e40afdc7980de0d3472799faf22177c6f61744bb1bf908375581b3c87e07733e6a87ea3683675d430832b1ed0955882"
    $a16="319f206d6ebcd3da5c811884af78811c11e487c3a89610d99c4948fdb166ecf6d20c5b624184fd41d6c87573ce88d2e6"
    $a17="e07ecbfcdee3199bb8752a4db479ff37e8bd51f0a670a50cb28681b0829c3f5eb7cead25f48da584ac0accbaa2e6ed70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}