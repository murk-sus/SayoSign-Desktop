// Known third-party SDKs, matched by bundled framework names, Info.plist keys and linked libraries.
// kind: ads | analytics | tracking | crash | social | payments | push | other

export const SDKS = [
  { name: "Google AdMob", kind: "ads", fw: /^GoogleMobileAds/, plist: ["GADApplicationIdentifier"], sym: ["GADMobileAds"] },
  { name: "AppLovin", kind: "ads", fw: /^AppLovinSDK/, plist: ["AppLovinSdkKey"], sym: ["ALSdk", "ALAdService"] },
  { name: "Unity Ads", kind: "ads", fw: /^UnityAds/, sym: ["UnityAds"] },
  { name: "ironSource / LevelPlay", kind: "ads", fw: /^(IronSource|ISAdapter)/, sym: ["IronSource"] },
  { name: "Meta Audience Network", kind: "ads", fw: /^FBAudienceNetwork/, sym: ["FBAdView", "FBInterstitialAd"] },
  { name: "Vungle / Liftoff", kind: "ads", fw: /^VungleAds|^VungleSDK/ },
  { name: "Mintegral", kind: "ads", fw: /^MTGSDK/, sym: ["MTGSDK"] },
  { name: "Pangle (ByteDance)", kind: "ads", fw: /^(PAGAdSDK|BUAdSDK)/, sym: ["PAGSdk", "BUAdSDKManager"] },
  { name: "InMobi", kind: "ads", fw: /^InMobiSDK/ },
  { name: "Chartboost", kind: "ads", fw: /^ChartboostSDK/ },
  { name: "Yandex Mobile Ads", kind: "ads", fw: /^YandexMobileAds/, sym: ["YMAMobileAds"] },
  { name: "AppsFlyer", kind: "tracking", fw: /^AppsFlyerLib/, sym: ["AppsFlyerLib"] },
  { name: "Adjust", kind: "tracking", fw: /^Adjust(Sdk)?\b/, sym: ["ADJConfig"] },
  { name: "Branch", kind: "tracking", fw: /^Branch/, plist: ["branch_key"], sym: ["BranchUniversalObject"] },
  { name: "Kochava", kind: "tracking", fw: /^Kochava/ },
  { name: "Singular", kind: "tracking", fw: /^Singular/ },
  { name: "Firebase Analytics", kind: "analytics", fw: /^(FirebaseAnalytics|GoogleAppMeasurement)/, sym: ["FIRAnalytics"] },
  { name: "Firebase", kind: "other", fw: /^Firebase(Core|Messaging|RemoteConfig|Auth|Firestore|Database|Installations)/, sym: ["FIRApp"] },
  { name: "Firebase Crashlytics", kind: "crash", fw: /^(FirebaseCrashlytics|Crashlytics|Fabric)/, sym: ["FIRCrashlytics"] },
  { name: "Amplitude", kind: "analytics", fw: /^Amplitude/, sym: ["AMPAmplitude", "AmplitudeSwift"] },
  { name: "Mixpanel", kind: "analytics", fw: /^Mixpanel/, sym: ["MixpanelInstance"] },
  { name: "Segment", kind: "analytics", fw: /^Segment/ },
  { name: "AppMetrica (Yandex)", kind: "analytics", fw: /^(YandexMobileMetrica|AppMetrica)/, sym: ["YMMYandexMetrica", "AMAAppMetrica"] },
  { name: "Flurry", kind: "analytics", fw: /^Flurry/, sym: ["FlurryAnalytics"] },
  { name: "Sentry", kind: "crash", fw: /^Sentry/, sym: ["SentrySDK"] },
  { name: "Bugsnag", kind: "crash", fw: /^Bugsnag/, sym: ["BugsnagConfiguration"] },
  { name: "Datadog", kind: "analytics", fw: /^Datadog/ },
  { name: "Facebook SDK", kind: "social", fw: /^(FBSDK|FacebookCore|FacebookLogin)/, plist: ["FacebookAppID"], sym: ["FBSDKApplicationDelegate"] },
  { name: "Google Sign-In", kind: "social", fw: /^GoogleSignIn/, sym: ["GIDSignIn"] },
  { name: "TikTok SDK", kind: "social", fw: /^TikTok/ },
  { name: "VK ID", kind: "social", fw: /^(VKID|VKSdk)/, sym: ["VKIDCore"] },
  { name: "OneSignal", kind: "push", fw: /^OneSignal/, sym: ["OneSignalFramework", "OSNotification"] },
  { name: "Braze", kind: "push", fw: /^(BrazeKit|Appboy)/, sym: ["BrazeKit", "Appboy"] },
  { name: "RevenueCat", kind: "payments", fw: /^RevenueCat/, sym: ["RCPurchases", "RevenueCat.Purchases"] },
  { name: "Stripe", kind: "payments", fw: /^Stripe/, sym: ["STPAPIClient"] },
  { name: "Adapty", kind: "payments", fw: /^Adapty/, sym: ["AdaptySDK", "Adapty"] },
  { name: "Qonversion", kind: "payments", fw: /^Qonversion/ },
  { name: "Realm", kind: "other", fw: /^Realm/ },
  { name: "Flutter", kind: "other", fw: /^Flutter\.framework$/ },
  { name: "React Native / Hermes", kind: "other", fw: /^(hermes|React)\.framework$/ },
  { name: "Unity engine", kind: "other", fw: /^UnityFramework/ },
  { name: "Xamarin / .NET", kind: "other", fw: /^(Xamarin|libmono|Microsoft\.)/ },
];

export const TRACKING_KINDS = new Set(["ads", "tracking", "analytics"]);

// Searches a binary for class-name strings of statically linked SDKs.
export function scanBinary(bin) {
  const text = new TextDecoder("latin1").decode(bin);
  const hits = new Set();
  for (const sdk of SDKS) {
    if ((sdk.sym || []).some((s) => text.includes(s))) hits.add(sdk.name);
  }
  return hits;
}

export function detectSDKs(r, binaryHits = new Set()) {
  const names = [...(r.frameworks || []), ...(r.linked || []).map((l) => l.split("/").pop())];
  const keys = new Set(Object.keys(r.info || {}));
  const found = [];
  for (const sdk of SDKS) {
    const byFw = names.some((n) => sdk.fw.test(n));
    const byPlist = (sdk.plist || []).some((k) => keys.has(k));
    if (byFw || byPlist || binaryHits.has(sdk.name)) found.push({ name: sdk.name, kind: sdk.kind });
  }
  return found;
}

// Simple fact-by-fact diff of two inspected IPAs.
export function compareIPAs(a, b) {
  const set = (x) => new Set(x || []);
  const diffList = (x, y) => ({ added: [...set(y)].filter((i) => !set(x).has(i)), removed: [...set(x)].filter((i) => !set(y).has(i)) });
  const fields = ["name", "bundleId", "version", "build", "minOS", "encrypted"];
  return {
    fields: fields.map((f) => ({ field: f, a: a[f], b: b[f], changed: String(a[f]) !== String(b[f]) })),
    size: { a: a.fileSize, b: b.fileSize },
    frameworks: diffList(a.frameworks, b.frameworks),
    plugins: diffList([...(a.plugins || []), ...(a.extensionKit || [])], [...(b.plugins || []), ...(b.extensionKit || [])]),
    injected: diffList(a.injected, b.injected),
    linked: diffList(a.linked, b.linked),
    looseDylibs: diffList(a.looseDylibs, b.looseDylibs),
    schemes: diffList(a.urlSchemes, b.urlSchemes),
    privacy: diffList(Object.keys(a.privacy || {}), Object.keys(b.privacy || {})),
    entitlements: diffList(Object.keys(a.entitlements || {}), Object.keys(b.entitlements || {})),
    sdks: diffList((a.sdks || []).map((s) => s.name), (b.sdks || []).map((s) => s.name)),
  };
}
