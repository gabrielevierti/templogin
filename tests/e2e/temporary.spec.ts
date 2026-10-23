import {test,expect} from '@playwright/test';
test('no-account TV handoff works in separate phone context, with revocation',async({browser,page})=>{
 const phoneContext=await browser.newContext({viewport:{width:390,height:844}});const phone=await phoneContext.newPage();
 const requests:string[]=[];phone.on('request',r=>requests.push(r.url()));
 try{
  await page.goto('/tv');await page.getByRole('button',{name:'Connect with tempLogin'}).click();
  const url=await page.locator('#verification-link').getAttribute('href');expect(url).toBeTruthy();
  await phone.goto(url!);await expect(phone.getByRole('heading',{name:/Your account.*Your provider/})).toBeVisible();
  await phone.getByRole('button',{name:'Continue with demo account'}).click();
  await expect(phone.getByRole('heading',{name:'Allow this TV?'})).toBeVisible();
  await phone.locator('#match').check();await phone.getByRole('button',{name:'Authorize this TV',exact:true}).click();
  await expect(phone.getByRole('heading',{name:'TV authorized.'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'You’re connected.'})).toBeVisible({timeout:15000});
  await phone.getByRole('link',{name:'Manage sessions'}).click();await phone.getByRole('button',{name:'Revoke access',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Session ended.'})).toBeVisible({timeout:15000});
  expect(requests.some(u=>/\/api\/(auth|me|connections)/.test(u))).toBe(false);
  expect(await phone.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }finally{await phoneContext.close();}
});
test('denied phone consent does not open a TV session',async({browser,page})=>{
 const context=await browser.newContext();const phone=await context.newPage();
 try{await page.goto('/tv');await page.getByRole('button',{name:'Connect with tempLogin'}).click();await phone.goto((await page.locator('#verification-link').getAttribute('href'))!);await phone.getByRole('button',{name:'Continue with demo account'}).click();await phone.getByRole('button',{name:'Decline request',exact:true}).click();await expect(page.getByRole('heading',{name:'Access declined.'})).toBeVisible({timeout:15000});}finally{await context.close();}
});
test('homepage and old account URLs never request registration or passkeys',async({page})=>{
 for(const path of ['/','/register','/login']){await page.goto(path);await expect(page.locator('h1')).toBeVisible();await expect(page.locator('button')).toHaveCount(0);}
 await page.setViewportSize({width:390,height:844});await page.goto('/tv');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
test('a short explicitly authorized session ends on TV without user action',async({browser,page})=>{
 const context=await browser.newContext();const phone=await context.newPage();
 try{
  await page.goto('/tv');await page.getByRole('button',{name:'Connect with tempLogin'}).click();
  const url=(await page.locator('#verification-link').getAttribute('href'))!;
  await phone.goto(url);await phone.getByRole('button',{name:'Continue with demo account'}).click();await expect(phone.getByRole('heading',{name:'Allow this TV?'})).toBeVisible();
  await phone.locator('#duration').selectOption('15');await phone.locator('#match').check();await phone.getByRole('button',{name:'Authorize this TV',exact:true}).click();
  await expect(page.getByRole('heading',{name:'You’re connected.'})).toBeVisible({timeout:10000});
  await expect(page.getByRole('heading',{name:/Your time is up\.|Session ended\./})).toBeVisible({timeout:20000});
 }finally{await context.close();}
});
test('English developer guide and small-screen routes remain usable',async({page})=>{
 const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));
 await page.setViewportSize({width:320,height:760});
 for(const path of ['/','/guide','/tv','/approve','/temporary-sessions']){
  await page.goto(path);await expect(page.locator('h1')).toBeVisible();
  expect(await page.locator('html').getAttribute('lang')).toBe('en');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),path).toBe(true);
 }
 await page.goto('/guide');await page.locator('.guide-nav').getByRole('link',{name:'03 · Integrate your app'}).click();
 await expect(page.getByRole('heading',{name:'Three connections to your app.'})).toBeInViewport();
 expect(errors).toEqual([]);
});
