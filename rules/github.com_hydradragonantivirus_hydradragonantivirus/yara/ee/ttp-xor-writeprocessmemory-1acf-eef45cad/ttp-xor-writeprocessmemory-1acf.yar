rule TTP_XOR_WriteProcessMemory_1acf {
  strings:
    $key_1acf = { 4d bd [2] 7f 9f [2] 79 aa [2] 57 aa [2] 68 b6 }

  condition:
    any of them
}