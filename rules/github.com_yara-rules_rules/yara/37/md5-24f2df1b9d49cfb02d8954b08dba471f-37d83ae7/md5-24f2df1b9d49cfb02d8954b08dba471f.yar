rule md5_24f2df1b9d49cfb02d8954b08dba471f {
    strings: $ = "))unlink('../media/catalog/category/'.basename($"
    condition: any of them
}