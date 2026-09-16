rule TTP_XOR_WriteProcessMemory_ca4a {
  strings:
    $key_ca4a = { 9d 38 [2] af 1a [2] a9 2f [2] 87 2f [2] b8 33 }

  condition:
    any of them
}