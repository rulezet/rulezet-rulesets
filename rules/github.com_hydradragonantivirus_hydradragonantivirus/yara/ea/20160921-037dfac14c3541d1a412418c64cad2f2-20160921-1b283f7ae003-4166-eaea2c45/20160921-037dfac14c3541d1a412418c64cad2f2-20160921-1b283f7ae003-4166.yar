rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_1b283f7ae003_4166 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash3       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash4       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash5       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash6       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "unction f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s2 = "p\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s3 = "{return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){" ascii
    $s5 = " \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}