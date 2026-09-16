rule TTP_XOR_WriteProcessMemory_f91a {
  strings:
    $key_f91a = { ae 68 [2] 9c 4a [2] 9a 7f [2] b4 7f [2] 8b 63 }

  condition:
    any of them
}