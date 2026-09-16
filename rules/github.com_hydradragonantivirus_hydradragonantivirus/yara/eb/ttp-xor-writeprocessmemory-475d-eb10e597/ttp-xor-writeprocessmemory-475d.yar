rule TTP_XOR_WriteProcessMemory_475d {
  strings:
    $key_475d = { 10 2f [2] 22 0d [2] 24 38 [2] 0a 38 [2] 35 24 }

  condition:
    any of them
}