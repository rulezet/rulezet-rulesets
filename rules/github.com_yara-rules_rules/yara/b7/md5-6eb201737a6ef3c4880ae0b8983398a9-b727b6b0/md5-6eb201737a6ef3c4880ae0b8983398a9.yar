rule md5_6eb201737a6ef3c4880ae0b8983398a9 {
    strings:
        $ = "if(md5(@$_COOKIE[qz])=="
        $ = "($_=@$_REQUEST[q]).@$_($_REQUEST[z]);"
    condition: all of them
}