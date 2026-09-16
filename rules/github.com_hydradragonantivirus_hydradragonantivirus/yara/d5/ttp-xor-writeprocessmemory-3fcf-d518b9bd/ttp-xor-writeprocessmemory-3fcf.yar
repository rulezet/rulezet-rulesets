rule TTP_XOR_WriteProcessMemory_3fcf {
  strings:
    $key_3fcf = { 68 bd [2] 5a 9f [2] 5c aa [2] 72 aa [2] 4d b6 }

  condition:
    any of them
}