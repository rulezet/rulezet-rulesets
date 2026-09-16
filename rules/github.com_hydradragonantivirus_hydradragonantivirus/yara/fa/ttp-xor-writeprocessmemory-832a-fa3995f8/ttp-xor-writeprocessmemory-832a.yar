rule TTP_XOR_WriteProcessMemory_832a {
  strings:
    $key_832a = { d4 58 [2] e6 7a [2] e0 4f [2] ce 4f [2] f1 53 }

  condition:
    any of them
}