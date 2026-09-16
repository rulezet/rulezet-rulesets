rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_523b4f49bbdc_4387 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash3       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash4       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash5       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"
    hash6       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash7       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\"" ascii
    $s2 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii
    $s3 = "unction f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s4 = "){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "a\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}