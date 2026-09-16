rule TTP_XOR_WriteProcessMemory_ca0a {
  strings:
    $key_ca0a = { 9d 78 [2] af 5a [2] a9 6f [2] 87 6f [2] b8 73 }

  condition:
    any of them
}