rule TTP_XOR_WriteProcessMemory_f51a {
  strings:
    $key_f51a = { a2 68 [2] 90 4a [2] 96 7f [2] b8 7f [2] 87 63 }

  condition:
    any of them
}