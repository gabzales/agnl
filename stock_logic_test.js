const fs = require('fs');
const ts = require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const vm = require('vm');

const source = fs.readFileSync(__dirname + '/server.js', 'utf8');
const sf = ts.createSourceFile('server.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const wanted = [
  '_dsFirst','_dsNormalizeName','_dsProviderNameCandidates','_dsNameMatch','_dsNameMatchWithAliases',
  'parseKeyDuration','isUsableLocalKey','isGenericKey','keyMatchesDuration','normalizeUsableLocalKeys',
  'countLocalDurationStock','countUsableLocalKeys','getLocalOptionStock','parseDurationLabel','formatDurationLabel',
  '_dsDurationFromText','_dsParseMoney','_dsMoneyCents','_dsFindVariantCost','_dsFindVariantExplicitStock','_dsExtractProductItems',
  'resolveDripstoreVariantFromCatalog','getDripstoreVirtualStock','findDripstoreVariantForOption',
  'getOptionStockView','normalizeProductBuyOptions','buildProductStockSummary'
];
const nodes = new Map();
function walk(n){
  if (ts.isFunctionDeclaration(n) && n.name && wanted.includes(n.name.text)) nodes.set(n.name.text,n);
  ts.forEachChild(n,walk);
}
walk(sf);
for (const name of wanted) if (!nodes.has(name)) throw new Error('Missing function in source: '+name);
let code = '';
// Alias table is the only required non-function constant for these helpers.
code += source.slice(source.indexOf('const DRIPSTORE_PRODUCT_ALIASES ='), source.indexOf('\n};', source.indexOf('const DRIPSTORE_PRODUCT_ALIASES ='))+3) + '\n';
for (const name of wanted) code += source.slice(nodes.get(name).pos, nodes.get(name).end) + '\n';
const ctx = { console, Math, Number, String, Set, Map, Array, Object, JSON };
vm.createContext(ctx);
vm.runInContext(code, ctx, {timeout: 2000});

function assert(cond,msg){ if(!cond) throw new Error('ASSERT FAILED: '+msg); }

assert(ctx._dsParseMoney('$1.40')===1.4,'$ money parse');
assert(ctx._dsParseMoney('USD 1,40')===1.4,'comma money parse');
assert(ctx._dsMoneyCents('$1.34')===134,'cents parse');
assert(Math.floor(ctx._dsMoneyCents('$1.34')/ctx._dsMoneyCents('$0.90'))===1,'balance/cost capacity');
assert(ctx._dsNameMatch('DRIP CLINT APK MOD','DRIP CLINT ROOT')===false,'no token-overlap false positive');
assert(ctx._dsNameMatch('AIM HACK','AIM HACK android+ ios')===true,'containment mapping');

const provider = {data:[
  {name:'AIM HACK android+ ios',variants:[
    {id:'v1',name:'1 jam',price:'$0.06'},
    {id:'v3',name:'3 hari',price:'$0.90'},
    {id:'v7',name:'7 hari',price:'$1.40'},
    {id:'v30',name:'30 hari',price:'$5.00'}
  ]},
  {name:'DRIP CLINT ROOT',variants:[{id:'root30',name:'30 hari',price:'$1.40'}]},
  {name:'Drip client apk mod',variants:[{id:'apk3',name:'3 hari',price:'$0.24'}]}
]};
const items = ctx._dsExtractProductItems(provider);
assert(items.some(x=>x.productName==='AIM HACK android+ ios' && x.days===3 && x.unit==='d' && x.variantId==='v3'),'provider extraction parent+variant');
assert(ctx.resolveDripstoreVariantFromCatalog(provider,'XREG APK MOD',{days:3,unit:'d'})==='v3','XREG alias resolves to AIM HACK 3d');
assert(ctx.resolveDripstoreVariantFromCatalog(provider,'DRIP CLINT APK MOD',{days:3,unit:'d'})==='apk3','explicit typo alias maps intended product');

const snapshot = {balance:'$1.34',products:provider};
assert(ctx.getDripstoreVirtualStock(snapshot,'v3')===1,'AIM 3d capacity 1');
assert(ctx.getDripstoreVirtualStock(snapshot,'v7')===0,'AIM 7d capacity 0');
assert(ctx.getDripstoreVirtualStock(snapshot,'v30')===0,'AIM 30d capacity 0');

const product = {name:'XREG APK MOD',status:'active',keys:['AAA=3d','BBB=3d','CCC=7d','Stok tidak tersedia:3'],pricingOptions:[
  {days:3,unit:'d',price:10000,dripstoreVariantId:'v3'},
  {days:7,unit:'d',price:20000,dripstoreVariantId:'v7'}
]};
const hybrid = ctx.buildProductStockSummary(product,{dripstore:{fulfillmentMode:'hybrid',apiToken:'x'}},snapshot);
assert(hybrid.stockByOption[0].localStock===2,'local 3d count exact');
assert(hybrid.stockByOption[0].providerStock===1,'provider 3d count');
assert(hybrid.stockByOption[0].stock===3,'hybrid 3d combined = 3');
assert(hybrid.stockByOption[1].localStock===1 && hybrid.stockByOption[1].providerStock===0 && hybrid.stockByOption[1].stock===1,'7d remains local 1 while provider unavailable');
assert(hybrid.stockCount===3,'product stock uses max option, not sum');

const liveUnmapped = ctx.getOptionStockView({name:'XREG APK MOD',keys:['AAA=3d']},{days:3,unit:'d',dripstoreVariantId:null},snapshot,'live',true);
assert(liveUnmapped.stock===1,'live resolves via current provider catalog');
const liveMissing = ctx.getOptionStockView({name:'UNKNOWN PRODUCT',keys:['AAA=3d']},{days:3,unit:'d',dripstoreVariantId:null},snapshot,'live',true);
assert(liveMissing.stock===0 && liveMissing.providerBacked===true && liveMissing.providerKnown===false,'live unmapped never exposes local stock');

const units = {name:'T',keys:['H=3h','D=3d'],pricingOptions:[{days:3,unit:'h',price:1},{days:3,unit:'d',price:2}]};
assert(ctx.getLocalOptionStock(units,units.pricingOptions[0])===1,'hour local stock exact');
assert(ctx.getLocalOptionStock(units,units.pricingOptions[1])===1,'day local stock exact');

console.log('STOCK LOGIC AUDIT: PASS');
console.log(JSON.stringify({
  xreg3d: hybrid.stockByOption[0],
  xreg7d: hybrid.stockByOption[1],
  productStockCount: hybrid.stockCount,
  providerCapacity:{aim3d:1,aim7d:0,aim30d:0}
},null,2));
