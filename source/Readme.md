#### Sniffer使用

```bash
Windows10（20H2）：
pip install -r requirements.txt
python main.py   # python版本须大于3.7
```

### 编译使用

```bash
pyinstaller --clean -F -w main.pyw -i .\image\exe.ico  
```

运行dist文件夹下的二进制文件即可
