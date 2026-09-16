rule TTP_XOR_WriteProcessMemory_dc5a {
  strings:
    $key_dc5a = { 8b 28 [2] b9 0a [2] bf 3f [2] 91 3f [2] ae 23 }

  condition:
    any of them
}