rule TTP_XOR_WriteProcessMemory_5ccf {
  strings:
    $key_5ccf = { 0b bd [2] 39 9f [2] 3f aa [2] 11 aa [2] 2e b6 }

  condition:
    any of them
}