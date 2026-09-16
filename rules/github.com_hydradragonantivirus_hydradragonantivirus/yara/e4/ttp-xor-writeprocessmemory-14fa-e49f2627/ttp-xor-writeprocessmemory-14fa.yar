rule TTP_XOR_WriteProcessMemory_14fa {
  strings:
    $key_14fa = { 43 88 [2] 71 aa [2] 77 9f [2] 59 9f [2] 66 83 }

  condition:
    any of them
}