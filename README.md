## Vol3_all_in_one

自动识别镜像系统（Windows / Linux / macOS），并发运行常用 Volatility3 插件，将每个插件输出保存到 `vol_output/` 目录下，便于在CTF比赛中快速获得内存镜像中的相关信息并方便下一步分析

用法：
```bash
python3 vol3_all_in_one.py image.raw [-full] [--timeout N]
```

运行截图：
![image](img/image.png)

说明：
- 在脚本内设置 `VOL3_PATH` 与 `VOL3_PLUGINS_PATH` 指向本地 Volatility3。 
- `-full` 显示每个插件的详细状态，默认显示进度条。 
- `--timeout` 指定单插件超时（秒），默认 `1200`。

输出示例：
```
vol_output/
	windows.pslist.PsList.txt
	linux.pslist.PsList.txt
	mac.pslist.PsList.txt
```
