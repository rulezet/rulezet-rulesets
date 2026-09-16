rule TTP_XOR_WriteProcessMemory_ca0d {
  strings:
    $key_ca0d = { 9d 7f [2] af 5d [2] a9 68 [2] 87 68 [2] b8 74 }

  condition:
    any of them
}