rule TTP_XOR_WriteProcessMemory_141a {
  strings:
    $key_141a = { 43 68 [2] 71 4a [2] 77 7f [2] 59 7f [2] 66 63 }

  condition:
    any of them
}