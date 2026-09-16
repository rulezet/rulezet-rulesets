rule php_false_positive_tiny: WEBSHELL PROD {
  meta:
    description = "PHP false positives"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/02/25"

  strings:
                $gfp_tiny3  = "include \"./common.php\";"      $gfp_tiny4  = "assert('FALSE');"
    $gfp_tiny5  = "assert(false);"
    $gfp_tiny6  = "assert(FALSE);"
    $gfp_tiny7  = "assert('array_key_exists("
    $gfp_tiny8  = "echo shell_exec($aspellcommand . ' 2>&1');"
    $gfp_tiny9  = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
    $gfp_tiny10 = "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

  condition:
    any of ($gfp_tiny*)
}