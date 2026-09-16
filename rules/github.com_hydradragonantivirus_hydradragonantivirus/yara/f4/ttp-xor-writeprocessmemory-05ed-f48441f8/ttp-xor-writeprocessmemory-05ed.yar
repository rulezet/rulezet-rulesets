rule TTP_XOR_WriteProcessMemory_05ed {
  strings:
    $key_05ed = { 52 9f [2] 60 bd [2] 66 88 [2] 48 88 [2] 77 94 }

  condition:
    any of them
}