rule TTP_XOR_WriteProcessMemory_dcfd {
  strings:
    $key_dcfd = { 8b 8f [2] b9 ad [2] bf 98 [2] 91 98 [2] ae 84 }

  condition:
    any of them
}