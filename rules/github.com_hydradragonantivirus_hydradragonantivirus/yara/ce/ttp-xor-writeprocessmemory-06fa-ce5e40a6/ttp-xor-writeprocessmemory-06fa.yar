rule TTP_XOR_WriteProcessMemory_06fa {
  strings:
    $key_06fa = { 51 88 [2] 63 aa [2] 65 9f [2] 4b 9f [2] 74 83 }

  condition:
    any of them
}