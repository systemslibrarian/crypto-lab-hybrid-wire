import { expect, test, type Page } from '@playwright/test';

type Rgb = [number, number, number];

async function completeHandshake(page: Page) {
  const next = page.locator('#next-step');
  await next.waitFor({ state: 'visible', timeout: 15_000 });

  for (let step = 0; step < 6; step += 1) {
    if (await next.isDisabled()) break;
    await next.click();
  }

  await page.locator('#message-input').waitFor({ state: 'visible' });
}

function luminance([red, green, blue]: Rgb) {
  const channels = [red, green, blue].map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(first: Rgb, second: Rgb) {
  const lighter = Math.max(luminance(first), luminance(second));
  const darker = Math.min(luminance(first), luminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

async function renderedBoundaryColors(page: Page) {
  return page.locator('.input').first().evaluate((input) => {
    const parse = (value: string) => {
      const values = value.match(/[\d.]+/g)?.map(Number) ?? [];
      return [values[0], values[1], values[2], values[3] ?? 1] as [number, number, number, number];
    };
    const composite = (
      foreground: [number, number, number, number],
      background: [number, number, number, number],
    ) => {
      const alpha = foreground[3] + background[3] * (1 - foreground[3]);
      return [
        (foreground[0] * foreground[3] + background[0] * background[3] * (1 - foreground[3])) / alpha,
        (foreground[1] * foreground[3] + background[1] * background[3] * (1 - foreground[3])) / alpha,
        (foreground[2] * foreground[3] + background[2] * background[3] * (1 - foreground[3])) / alpha,
        alpha,
      ] as [number, number, number, number];
    };

    const layers: [number, number, number, number][] = [];
    for (let element: Element | null = input; element; element = element.parentElement) {
      layers.push(parse(getComputedStyle(element).backgroundColor));
    }
    let background: [number, number, number, number] = [255, 255, 255, 1];
    for (const layer of layers.reverse()) background = composite(layer, background);

    const border = parse(getComputedStyle(input).borderTopColor);
    return {
      border: border.slice(0, 3) as Rgb,
      background: background.slice(0, 3) as Rgb,
    };
  });
}

for (const theme of ['dark', 'light'] as const) {
  test(`${theme} input boundaries retain 3:1 contrast`, async ({ page }) => {
    await page.goto('/');
    if (theme === 'light') await page.locator('#cl-theme-toggle').click();
    await completeHandshake(page);

    const colors = await renderedBoundaryColors(page);
    expect(contrast(colors.border, colors.background)).toBeGreaterThanOrEqual(3);
  });
}
