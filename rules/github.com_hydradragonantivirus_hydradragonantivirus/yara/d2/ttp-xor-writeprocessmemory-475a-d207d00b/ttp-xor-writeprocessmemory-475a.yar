rule TTP_XOR_WriteProcessMemory_475a {
  strings:
    $key_475a = { 10 28 [2] 22 0a [2] 24 3f [2] 0a 3f [2] 35 23 }

  condition:
    any of them
}