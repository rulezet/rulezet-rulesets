rule TTP_XOR_WriteProcessMemory_04fa {
  strings:
    $key_04fa = { 53 88 [2] 61 aa [2] 67 9f [2] 49 9f [2] 76 83 }

  condition:
    any of them
}