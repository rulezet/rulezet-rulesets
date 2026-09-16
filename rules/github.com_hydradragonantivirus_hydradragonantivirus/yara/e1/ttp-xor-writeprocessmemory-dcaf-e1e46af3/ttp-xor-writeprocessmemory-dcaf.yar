rule TTP_XOR_WriteProcessMemory_dcaf {
  strings:
    $key_dcaf = { 8b dd [2] b9 ff [2] bf ca [2] 91 ca [2] ae d6 }

  condition:
    any of them
}