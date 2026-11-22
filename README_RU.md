<p align="center"><img src="sayosign_desktop/web/icon.png" width="96" alt="SayoSign"></p>
<h1 align="center">SayoSign Desktop</h1>
<p align="center">
  <b>Подпись и установка IPA на айфон с Linux, Windows и macOS.</b><br>
  .p12 или Apple ID · инжект твиков · рабочий вход через Apple ID в 2026 · anisette-сервер на твоём ПК
</p>
<p align="center"><a href="https://github.com/murk-sus/SayoSign-Desktop/releases/latest"><b>⬇ Скачать</b></a> · <a href="README.md">English</a> · <a href="https://github.com/murk-sus/SayoSign">iOS-приложение</a></p>

## Что умеет

- **Подпись и установка по USB** с прогрессом или только подпись и скачивание. Своё окно, без вкладки браузера.
- **Сертификаты**: `.p12` + `.mobileprovision` с живой проверкой отзыва (OCSP) или **вход через бесплатный или платный Apple ID** — сертификат, регистрация айфона и профиль для каждого приложения создаются сами.
- **Твики**: инжект `.deb` и `.dylib`.
- **Вкладка Anisette**: быстрая настройка, свой сервер, данные сервера и **anisette-сервер на этом ПК** для айфона (через QR-код).
- Темы: Авто, Светлая, **Чёрная**. English, Русский, 中文.

## Почему в октябре 2026 сломался вход через Apple ID

С середины октября Apple отклоняет anisette, не совпадающий с клиентом, для которого он сделан:
- anisette на **Android**-библиотеках (а на Linux/Windows другого не бывает: `ani.sidestore.io`, `ani.sidestore.zip`, свой `anisette-v3-server`) даёт `-80045`, HTTP `503` или `401` на `finishMachineProvisioning`;
- старая строка клиента Xcode `3594.4.19` отклоняется;
- **Mac-серверы** работают, если в каждом запросе отправлять client info и user agent самого сервера.

SayoSign Desktop поэтому говорит по **протоколу anisette v3**, шлёт client info сервера во всех запросах к Apple, берёт адреса из URL-bag Apple, доверяет корню Apple для `gsa.apple.com`, держит в пресетах только Mac-серверы, умеет сам выбрать самый быстрый, понятно объясняет коды ошибок и один раз повторяет вход с новой идентичностью anisette.

Проверено с Apple 22.11.2026: provisioning проходит, а `init` GrandSlam возвращает SRP-вызов через все пресеты и через релей на ПК.

### Anisette-сервер на твоём ПК

Сам ПК не может выдать Mac-anisette, поэтому SayoSign запускает **релей**: включи «Anisette-сервер на этом ПК», и компьютер начнёт раздавать полный протокол v3 в твоей Wi-Fi (`http://<твой-ip>:6969`), опираясь на выбранный сервер (пресет или твой Mac-сервер). Отсканируй QR камерой айфона — откроется SayoSign и сервер установится сам.

## Установка (Linux)
```sh
git clone --recursive https://github.com/murk-sus/SayoSign-Desktop && cd SayoSign-Desktop
./install-linux.sh
sayosign-desktop
```
Windows / macOS — сборки в [Releases](https://github.com/murk-sus/SayoSign-Desktop/releases).

💖 Поддержать: **[murk-sus.github.io/donate](https://murk-sus.github.io/donate/)** · Telegram [@jailbreak_IOS_and_tweaks](https://t.me/jailbreak_IOS_and_tweaks)
