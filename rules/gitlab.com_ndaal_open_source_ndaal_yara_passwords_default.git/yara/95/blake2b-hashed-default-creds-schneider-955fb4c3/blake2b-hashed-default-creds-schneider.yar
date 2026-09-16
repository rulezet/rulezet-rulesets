rule blake2b_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fc453313c9f389f8121626d76498cbe6585bcbd077500c309cee6902ee1bc765c2c8472329ca16cc4c973599677a68de93fabf4f2831dcf245177f0e950c720"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="2ab8959cd324808fe15e7ee1b27a752a10a5ccf33dbabaee4ed1a3789a474d82942b6fc735605eea40a864310629a8997c94d6e71fb2f9351beee8fc4575a813"
    $a3="413df10a2188383f99931bbbe5d37d8211dc0f972bea9347b1ff7d1351cc57a541541317080ba298fc94e0df68588ae789fc45e8277e88f97c49938005e89432"
    $a4="3408a118fbd016d158e863484224429aacbad25adff8f2b88ef321ca78ead49b57809d7740ba4156037315119c559533982b1057ba0c89fc65549087a9bb2b81"
    $a5="037353dc33994142e36d08f363b05279a50faf390f719b54f7ff4d0a42193c257596446f0c826ce3eb54eca9095e864dc93568ac8b388437e66f181b4b3a0a1a"
    $a6="69b451e1e89a11444b8cbdade33cd94c1b519f2a7fdf08e64f062a023878b46b3a306e0c5f4ab91c1167b3a4806f1f83eddf2897879730dd0f6c13db92b4040c"
    $a7="33729a49dc84a798f8afdea91c57c4c886b6e5bff3747bf00a50b15a58748aeb08c8c53613f169546e6e75a4ff7d9954420bf505a71d712241965466815127ac"
    $a8="1eb32b2f1ce876fac529b7928657c1b8f885d75663eb082bd07d212ccfd7ea5dc890beacc5d26f47fe2ade13b45cbbc6be0f3b0614e83dd5ec8daf0b8b6bc29a"
    $a9="4548f269ecb8d41644522baed22de8734e3499897742b59ac51cd442e8fbfbc3d19866cdbd7a917e85fa99440e3c5dae7633a78433ecc39b97510fc21ee1c522"
    $a10="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a11="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a12="00b9b7ad478a8e6e71d31b03d7a1d77c6ff921280456c8cb34695b3bb6e7c4ba139c3a70e9f51ab2f3e95837e5d5dbf06560917e1f83a67d615b94f6f3e6c9c3"
    $a13="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}