rule infected_09_06_18_shells_us1 {
  meta:
    description = "shells - file us1.PhP"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "82ec6b0c75d69fd398866088837b7f11b5b5633d63d61b272422681455a6d54d"

  strings:
    $s1  = "$bhrt = \"eNrsvXtXG0fSOPw3e85+h/YsyUgbISGuDliyscExWQwEcLJZ20fvSDNCYySNMiNxSda/z/5WVV+me24SIDnJPiExSH2prq6urq7urq569nzUG/39by8ib9" ascii
    $s2  = "$ind = \"WW91IGp1c3QgZ290IGhhY2tlZCAhISEhIQ==\"; // \"Deface Page\" Base64 encoded \"You Just Got Hacked !!\"" fullword ascii
    $s3  = "//====+++Coded By Arjun+++===//" fullword ascii
    $s4  = "$malsite = \"http://fightagent.ru\";  // Malware Site" fullword ascii
    $s5  = "7ebW9evr05uc30dndmfP09c+jH87Pvv3h33uDVy9v33wfXr09/7R/3LuqjfZqJ99MXk/ubjc/OdefNr77z1H46/eftp7e/nrU+8/F2S9vnzrffeocexu97//19nDj/Lw" ascii
    $s6  = "eval(\"?>\".gzuncompress(base64_decode($bhrt))); ?>" fullword ascii
    $s7  = "// Set Username & Password" fullword ascii
    $s8  = "4z3jv37bhj1s+RwEB+gtrGHieHxwdvLpg/+S2Kez/MxCGQfSGET4p+/+YlfD+jy91GAHUGeOeDcjNf4veU0ErfAHh8VdavtuwV20GQ8zQ4r9h11W3SDnJs4n5RXcHTeB" ascii
    $s9  = "ek40GRXb60Zp++2Dkpi+9VcQV3ZJ47I/7XtHWREnZeyn18kI9Hy7LPY1Gq45xMCBXqenHJBj78cYtlavL5wene2d7FydnPFTPlG2HcHA648Yv3/BhFrq9hZHPbMrNsTs" ascii
    $s10 = "SboffeIEt4uz9hAYEbxbFFs5uGIWvTCb1bhxZW/k3+rb7Q5rT8tsW9L5zrN+P7P40s120saRTAm4/0aeYeLlrKSb60+r6OzFROvJkIRWR8HYuh2mAujMNN73XDOB1nja" ascii
    $s11 = "82WhkNnpbnWwz+dy5rjxpnVr16rJVNU5SvdPN+5fqUf9lszRSzk7axeRUzeYy54db28eV26pVuFSPy+P7RDU66FaempcD62Ryn5W1c22UrW/clrTTgrFxVd84rY8PTsb" ascii
    $s12 = "pAmjZ50ah/Is8hbbZLkv59GIlKPyswbblI1Ymb9phZWoQ7oD4V2x9XVZeHtOzhGjSxpfZvB8V8tVFtpuylDzYpb9VhrVUnv/NN+LzZwMj4TKR6mgySVESmC/01q7X8Dn" ascii
    $s13 = "kLjN/m3eWgEt1FFss6OipBKM4tlvAeZqKqoVZkcR6MiLYNM20DzCYivCr7s4gzeb7Da07bjIEnxvLFeANFLHCZt5vfs0cKp2cn9SIkBBbTzrmXgsmLyN+P5xypVCsoIM" ascii
    $s14 = "+PR+H/vCyoghWjt97CICJdxnyWkO0VuEIq2cm8kJD1FVvWQSxv/nGeGKBzQhaNhuKwIkW815m8L3tfhCxV8FgBIoomuG31S5XZJ+cMxExw7l0/CHsgBRNdogirCNrgxB" ascii
    $s15 = "LrazgS8UdZlW14kYN0VFZ48Pww3Cl8OfDMAns20SYis/SPyoeJqGHgtCLfNCnxgr9F0CNsdcLQBmpXgbXVhwS9wmykcEcldSAVfVuVlIjVtX7VLFeQ5s7KFjgb4qeZP+" ascii
    $s16 = "Fq5jd9mW95dykorljZLgiIiQBEOl73B1mDiRCxwV/jXgok/Nn1hfP5vGr41XDmUBku4P4ic1I1lKhL7hBzmvaUcU+6sO+YqpNb975H6Ek8FNyzgIHGTAXueVYeNcDBX3" ascii
    $s17 = "ignF6YQKX5EoIRD2v34/Gd32vJKQ1gbeeURobAxUaH6yxdzuudaLog9X8+9+ePVlZwfWyHbh3lbFbGfeIVTpBPwh32D9ev16FH8SgC5RZQTLssPrG6HaXWvaHsPpW25O" ascii
    $s18 = "QbQYmi8FJJFSztcdlUwmUUG45iQfTCq+qe8ndVfUjTFfQoOFCkd1VMWTWqt5u7UH651X1C7fY+N1oPDY1RdZp0xFC3YBLFztIvHJhNG3FXsPysCL3pXnFaNCuHSTF23w" ascii
    $s19 = "O+sGNB6paDKZcVTN1d+o80HukpkB6AmT01mR7nRMfQWBtWv5v0TmjY48n959d1pD7gXxpwy1EC8QNL/A7yJu8FTPBEPEDDT725QctkUglbYnET63clUrTt1pzXRsf1ey" ascii
    $s20 = "bINcQpNQ1iTau5V6DpBmH/qAEqbtC6IsCuhWE/QwE7TAhBtBWbnmIRnE7TAkCKmdLCxq8UBkFIL2uK8yCIcZzowbrOv3IK/N1UoDXAK9xwNcIWIIF1UXAxBMpo+Yo9MQ" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 200KB and
      (8 of them)
    ) or (all of them)
}