rule TTP_XOR_WriteProcessMemory_62fd {
  strings:
    $key_62fd = { 35 8f [2] 07 ad [2] 01 98 [2] 2f 98 [2] 10 84 }

  condition:
    any of them
}