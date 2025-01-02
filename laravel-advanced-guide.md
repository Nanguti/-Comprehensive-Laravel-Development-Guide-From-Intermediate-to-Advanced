# Comprehensive Laravel Development Guide: From Intermediate to Advanced

## Table of Contents

1. [Middleware](#middleware)
2. [Authentication and Authorization](#authentication-and-authorization)
3. [Advanced Eloquent](#advanced-eloquent)
4. [APIs](#apis)
5. [Task Scheduling](#task-scheduling)
6. [Events and Listeners](#events-and-listeners)
7. [Advanced Authentication](#advanced-authentication)
8. [Queues and Jobs](#queues-and-jobs)
9. [Testing](#testing)
10. [Custom Packages](#custom-packages)
11. [Performance Optimization](#performance-optimization)
12. [Multi-tenancy](#multi-tenancy)
13. [Server Deployment](#server-deployment)
14. [Capstone Projects](#capstone-projects)

## Middleware

### Creating Custom Middleware

Middleware acts as a filtering layer for HTTP requests. Understanding middleware is crucial for request/response manipulation.

#### Types of Middleware:

1. **Global Middleware**: Runs on every HTTP request
2. **Route Middleware**: Assigned to specific routes
3. **Group Middleware**: Applied to route groups
4. **Terminable Middleware**: Executes after response is sent to browser

Example of a comprehensive middleware:

```php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class LogRequestMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Pre-processing
        $startTime = microtime(true);

        // Log incoming request
        Log::info('Incoming request', [
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'headers' => $request->headers->all()
        ]);

        // Continue to next middleware/controller
        $response = $next($request);

        // Post-processing
        $duration = microtime(true) - $startTime;

        // Log response
        Log::info('Response sent', [
            'duration' => $duration,
            'status' => $response->status(),
            'content_type' => $response->headers->get('Content-Type')
        ]);

        return $response;
    }

    public function terminate($request, $response)
    {
        // Perform cleanup after response is sent to browser
    }
}
```

### Registering Middleware

```php
// In app/Http/Kernel.php

protected $middleware = [
    // Global middleware
    \App\Http\Middleware\LogRequestMiddleware::class,
];

protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
    ],
    'api' => [
        'throttle:api',
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ],
];

protected $routeMiddleware = [
    'auth' => \App\Http\Middleware\Authenticate::class,
    'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
    'signed' => \Illuminate\Routing\Middleware\ValidateSignature::class,
];
```

## Authentication and Authorization

### Advanced Authentication Strategies

#### Custom Guards

```php
namespace App\Guards;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class TokenGuard implements Guard
{
    protected $provider;
    protected $request;
    protected $user;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    public function check()
    {
        return !is_null($this->user());
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $token = $this->request->bearerToken();

        if (!$token) {
            return null;
        }

        // Implement your token validation logic here
        $user = $this->provider->retrieveById($userId);

        return $this->user = $user;
    }
}
```

### Role-Based Access Control (RBAC)

#### Database Structure

```sql
CREATE TABLE roles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL
);

CREATE TABLE permissions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL
);

CREATE TABLE role_user (
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE permission_role (
    role_id BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
```

#### Role and Permission Models

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Role extends Model
{
    protected $fillable = ['name', 'slug', 'description'];

    public function permissions()
    {
        return $this->belongsToMany(Permission::class);
    }

    public function users()
    {
        return $this->belongsToMany(User::class);
    }

    public function hasPermission($permission)
    {
        return $this->permissions()->where('slug', $permission)->exists();
    }
}

class Permission extends Model
{
    protected $fillable = ['name', 'slug', 'description'];

    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }
}
```

#### User Trait for RBAC

```php
namespace App\Traits;

trait HasRoles
{
    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }

    public function hasRole($role)
    {
        if (is_string($role)) {
            return $this->roles->contains('slug', $role);
        }

        return !! $role->intersect($this->roles)->count();
    }

    public function hasPermission($permission)
    {
        return $this->roles()->whereHas('permissions', function ($query) use ($permission) {
            $query->where('slug', $permission);
        })->exists();
    }

    public function assignRole($role)
    {
        if (is_string($role)) {
            $role = Role::where('slug', $role)->firstOrFail();
        }

        $this->roles()->sync($role, false);
    }

    public function removeRole($role)
    {
        if (is_string($role)) {
            $role = Role::where('slug', $role)->firstOrFail();
        }

        $this->roles()->detach($role);
    }
}
```

## Advanced Eloquent

### Complex Relationships

#### Polymorphic Relations

```php
class Image extends Model
{
    public function imageable()
    {
        return $this->morphTo();
    }
}

class User extends Model
{
    public function images()
    {
        return $this->morphMany(Image::class, 'imageable');
    }
}

class Product extends Model
{
    public function images()
    {
        return $this->morphMany(Image::class, 'imageable');
    }
}
```

#### Custom Pivot Tables with Extra Attributes

```php
class User extends Model
{
    public function roles()
    {
        return $this->belongsToMany(Role::class)
            ->withPivot('expired_at', 'granted_by')
            ->withTimestamps();
    }
}
```

### Query Scopes and Global Scopes

```php
class Post extends Model
{
    // Local scope
    public function scopePublished($query)
    {
        return $query->where('status', 'published')
                    ->where('published_at', '<=', now());
    }

    public function scopePopular($query, $minViews = 1000)
    {
        return $query->where('views', '>=', $minViews);
    }

    // Global scope
    protected static function booted()
    {
        static::addGlobalScope('active', function ($query) {
            $query->where('is_active', true);
        });
    }
}
```

### Advanced Query Building

```php
// Complex queries with sub-selects
$popularPosts = Post::addSelect(['last_comment' => Comment::select('content')
    ->whereColumn('post_id', 'posts.id')
    ->latest()
    ->limit(1)
])
->withCount(['comments', 'likes'])
->having('comments_count', '>=', 10)
->orderBy('views', 'desc')
->get();

// Using Raw Expressions
$users = User::select(DB::raw('COUNT(*) as user_count, status'))
    ->where('status', '<>', 'deleted')
    ->groupBy('status')
    ->having('user_count', '>', 10)
    ->get();

// Complex Joins
$posts = Post::select('posts.*', 'users.name as author_name')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->leftJoin('categories', 'posts.category_id', '=', 'categories.id')
    ->whereExists(function ($query) {
        $query->select(DB::raw(1))
            ->from('comments')
            ->whereColumn('comments.post_id', 'posts.id');
    })
    ->get();
```

## APIs

### RESTful API Best Practices

#### API Resource Collections

```php
namespace App\Http\Resources;

class PostResource extends JsonResource
{
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'content' => $this->when(!$request->is('api/posts'), $this->content),
            'created_at' => $this->created_at->toISO8601String(),
            'author' => new UserResource($this->whenLoaded('author')),
            'comments_count' => $this->when(
                $request->include_counts,
                $this->comments_count
            ),
            'links' => [
                'self' => route('posts.show', $this->id),
                'comments' => route('posts.comments.index', $this->id),
            ],
            'meta' => [
                'views' => $this->views,
                'reading_time' => $this->calculateReadingTime(),
            ],
        ];
    }

    public function with($request)
    {
        return [
            'status' => 'success',
            'version' => '1.0',
            'server_time' => now()->toISO8601String(),
        ];
    }
}
```

#### API Response Traits

```php
namespace App\Traits;

trait ApiResponse
{
    protected function success($data, $message = null, $code = 200)
    {
        return response()->json([
            'status' => 'success',
            'message' => $message,
            'data' => $data
        ], $code);
    }

    protected function error($message, $code = 400)
    {
        return response()->json([
            'status' => 'error',
            'message' => $message,
        ], $code);
    }

    protected function pagination($items, $message = null)
    {
        return response()->json([
            'status' => 'success',
            'message' => $message,
            'data' => $items->items(),
            'meta' => [
                'current_page' => $items->currentPage(),
                'last_page' => $items->lastPage(),
                'per_page' => $items->perPage(),
                'total' => $items->total(),
            ],
            'links' => [
                'first' => $items->url(1),
                'last' => $items->url($items->lastPage()),
                'prev' => $items->previousPageUrl(),
                'next' => $items->nextPageUrl(),
            ],
        ]);
    }
}
```

## Task Scheduling

### Advanced Task Scheduling

```php
namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    protected function schedule(Schedule $schedule)
    {
        // Complex scheduling with constraints
        $schedule->command('emails:send')
            ->weekdays()
            ->hourly()
            ->between('8:00', '17:00')
            ->whenDatabaseHas('queue_monitors', [
                'status' => 'ready',
                'type' => 'email'
            ])
            ->before(function () {
                // Preparation tasks
            })
            ->after(function () {
                // Cleanup tasks
            })
            ->onSuccess(function () {
                // Success handling
            })
            ->onFailure(function () {
                // Failure handling
            });

        // Overlapping prevention
        $schedule->command('reports:generate')
            ->dailyAt('01:00')
            ->withoutOverlapping()
            ->runInBackground()
            ->appendOutputTo(storage_path('logs/reports.log'));

        // Maintenance tasks
        $schedule->call(function () {
            // Clear old temporary files
        })->weekly()->saturdays()->at('00:00')
            ->when(function () {
                return storage_path('app/temp')->exists();
            });
    }
}
```

## Events and Listeners

### Advanced Event Handling

#### Event with Broadcasting

```php
namespace App\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class OrderShipped implements ShouldBroadcast
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public $order;
    private $user;

    public function __construct($order, $user)
    {
        $this->order = $order;
        $this->user = $user;
    }

    public function broadcastOn()
    {
        return [
            new Channel('orders'),
            new PrivateChannel('users.' . $this->user->id),
        ];
    }

    public function broadcastWith()
    {
        return [
            'order_id' => $this->order->id,
            'status' => $this->order->status,
            'timestamp' => now()->toISO8601String(),
        ];
    }

    public function broadcastAs()
    {
        return 'order.shipped';
    }
}
```

[Previous sections remain the same...]

#### Complex Event Listeners

```php
namespace App\Listeners;

class OrderShippedListener implements ShouldQueue
{
    use InteractsWithQueue;

    public $tries = 3;
    public $backoff = [60, 180, 360];

    public function handle(OrderShipped $event)
    {
        if ($this->shouldRetry()) {
            $this->release(60);
            return;
        }

        // Process shipping notification
        Notification::send(
            $event->order->customer,
            new OrderShippedNotification($event->order)
        );

        // Update inventory
        $this->updateInventory($event->order);

        // Trigger third-party integrations
        $this->notifyExternalServices($event->order);
    }

    private function shouldRetry()
    {
        // Custom retry logic
        return false;
    }
}
```

## Testing

### Advanced Testing Techniques

#### Custom Test Cases

```php
namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;

    protected function setUp(): void
    {
        parent::setUp();

        // Disable event handling
        Event::fake();

        // Disable queue processing
        Queue::fake();

        // Custom test database setup
        $this->setupTestDatabase();
    }

    protected function setupTestDatabase()
    {
        // Custom database setup logic
    }

    protected function assertModelExists($model)
    {
        $this->assertTrue($model->exists);
        $this->assertDatabaseHas($model->getTable(), [
            $model->getKeyName() => $model->getKey(),
        ]);
    }
}
```

#### Feature Tests with Authentication

```php
namespace Tests\Feature;

use App\Models\User;
use Tests\TestCase;
use Laravel\Sanctum\Sanctum;

class OrderControllerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Create test data
        $this->user = User::factory()->create();
        $this->order = Order::factory()
            ->for($this->user)
            ->create();
    }

    public function test_user_can_view_their_orders()
    {
        Sanctum::actingAs($this->user);

        $response = $this->getJson('/api/orders');

        $response
            ->assertStatus(200)
            ->assertJson([
                'data' => [
                    [
                        'id' => $this->order->id,
                        'status' => $this->order->status,
                    ]
                ]
            ]);
    }

    public function test_user_cannot_view_others_orders()
    {
        $otherUser = User::factory()->create();
        Sanctum::actingAs($otherUser);

        $response = $this->getJson("/api/orders/{$this->order->id}");

        $response->assertStatus(403);
    }
}
```

## Performance Optimization

### Caching Strategies

#### Advanced Cache Implementation

```php
namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;

class CacheService
{
    public function remember($key, $callback, $ttl = 3600)
    {
        // Use Redis for atomic locks
        $lock = Redis::lock($key . '_lock', 10);

        try {
            if ($lock->get()) {
                $value = $callback();
                Cache::put($key, $value, $ttl);
                return $value;
            }

            // Wait for lock to release and return cached value
            return Cache::get($key, function () use ($callback, $key, $ttl) {
                $value = $callback();
                Cache::put($key, $value, $ttl);
                return $value;
            });
        } finally {
            optional($lock)->release();
        }
    }

    public function tags($tags, $callback)
    {
        return Cache::tags($tags)->remember(
            $this->generateCacheKey($tags),
            3600,
            $callback
        );
    }

    private function generateCacheKey(array $tags): string
    {
        return md5(implode('_', $tags));
    }
}
```

### Query Optimization

```php
namespace App\Services;

class QueryOptimizer
{
    public function optimizeQuery($query)
    {
        return $query
            ->select($this->getRequiredColumns())
            ->with($this->getRequiredRelations())
            ->whereHas('relationName', function ($q) {
                $q->select('id')->whereActive(true);
            })
            ->chunk(100, function ($records) {
                foreach ($records as $record) {
                    // Process records in chunks
                }
            });
    }

    protected function getRequiredColumns()
    {
        // Return only needed columns
        return ['id', 'name', 'email'];
    }

    protected function getRequiredRelations()
    {
        // Return only needed relations
        return ['profile:id,user_id,avatar'];
    }
}
```

## Multi-tenancy

### Database Multi-tenancy

```php
namespace App\Traits;

trait MultiTenant
{
    public static function bootMultiTenant()
    {
        static::creating(function ($model) {
            $model->tenant_id = session('tenant_id');
        });

        static::addGlobalScope('tenant', function ($query) {
            $query->where('tenant_id', session('tenant_id'));
        });
    }

    public function tenant()
    {
        return $this->belongsTo(Tenant::class);
    }
}
```

### Tenant Configuration

```php
namespace App\Services;

class TenantManager
{
    protected $tenant;

    public function setTenant($tenant)
    {
        $this->tenant = $tenant;

        // Switch database connection
        config([
            'database.connections.tenant.database' => $tenant->database_name
        ]);

        // Set tenant-specific configs
        config([
            'app.name' => $tenant->app_name,
            'mail.from.address' => $tenant->email_from,
        ]);

        // Set tenant session
        session(['tenant_id' => $tenant->id]);
    }

    public function getTenant()
    {
        return $this->tenant;
    }
}
```

## Server Deployment

### Deployment Script

```php
namespace App\Console\Commands;

use Illuminate\Console\Command;

class DeployApplication extends Command
{
    protected $signature = 'app:deploy {environment}';

    public function handle()
    {
        $this->info('Starting deployment...');

        // Maintenance mode
        $this->call('down');

        try {
            // Backup database
            $this->backup();

            // Pull latest changes
            $this->git();

            // Install dependencies
            $this->composer();

            // Optimize application
            $this->optimize();

            $this->info('Deployment completed successfully!');
        } catch (\Exception $e) {
            $this->error('Deployment failed: ' . $e->getMessage());

            // Rollback changes if needed
            $this->rollback();
        } finally {
            // Disable maintenance mode
            $this->call('up');
        }
    }

    protected function backup()
    {
        // Implementation
    }

    protected function git()
    {
        // Implementation
    }

    protected function composer()
    {
        // Implementation
    }

    protected function optimize()
    {
        $this->call('config:cache');
        $this->call('route:cache');
        $this->call('view:cache');
    }

    protected function rollback()
    {
        // Implementation
    }
}
```

## Capstone Projects

### Advanced E-commerce Platform

#### Key Features:

1. Multi-vendor support
2. Real-time inventory management
3. Advanced search with ElasticSearch
4. Payment gateway integration
5. Order processing workflow
6. Analytics dashboard
7. API integration
8. Multi-language support

#### Sample Implementation Structure

```php
namespace App\Services\Ecommerce;

class OrderProcessor
{
    public function process(Order $order)
    {
        DB::transaction(function () use ($order) {
            // Verify inventory
            $this->verifyInventory($order);

            // Process payment
            $this->processPayment($order);

            // Update inventory
            $this->updateInventory($order);

            // Notify stakeholders
            $this->notifyStakeholders($order);

            // Generate invoice
            $this->generateInvoice($order);
        });
    }

    // Implementation of individual methods...
}
```
