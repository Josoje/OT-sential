import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('navigation and API integration', () => {
  it('opens the event view and loads event records from the API', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.endsWith('/health')
        ? {status:'ok',environment:'DEMO',database:'tilgængelig',live_sources:0}
        : url.includes('/dashboard')
          ? {metrics:{total_events:1,open_incidents:0,critical_high:0,assets:1,active_sources:1,last_ingestion:'2026-10-28T12:00:00Z'},severity:{Kritisk:0,Høj:0,Middel:0,Lav:1,Information:0},timeline:[],events:[],recommendations:[],assets:[]}
          : {items:[{id:'event-1',timestamp:'2026-10-28T12:00:00Z',event_type:'network_connection',severity:'Lav',source_asset:'demo-ws',source:'Syntetisk',description:'Godkendt testforbindelse',status:'Ny',risk_score:10,evidence:[]}],total:1,page:1,page_size:100};
      return new Response(JSON.stringify(body),{status:200,headers:{'Content-Type':'application/json'}});
    }));
    render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><App/></QueryClientProvider>);
    fireEvent.click(screen.getByRole('button',{name:'Hændelser'}));
    expect(await screen.findByText('Godkendt testforbindelse')).toBeTruthy();
    expect(screen.getByRole('heading',{name:'Sikkerhedshændelser'})).toBeTruthy();
  });
});
