rule TTP_XOR_WriteProcessMemory_ca6a {
  strings:
    $key_ca6a = { 9d 18 [2] af 3a [2] a9 0f [2] 87 0f [2] b8 13 }

  condition:
    any of them
}